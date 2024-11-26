const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const pool = require('./db');

const app = express();
const port = 7197;
const cors = require('cors');

// 添加 CORS 中间件
app.use(cors());

app.use(bodyParser.json());

require('dotenv').config();

const SECRET_KEY = process.env.SECRET_KEY;

// 登录接口
app.post('/admin/acl/index/login', async (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM users WHERE username = $1';

  try {
      const result = await pool.query(query, [username]);

      // 如果没有找到用户
      if (result.rows.length === 0) {
          return res.status(401).json({ code: 401, message: 'Invalid username or password' });
      }

      // 验证密码
      const user = result.rows[0];
      if (bcrypt.compareSync(password, user.password)) {
          const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
          return res.json({ code: 200, data: { token: token } });
      } else {
          return res.status(401).json({ code: 401, message: 'Invalid username or password' });
      }
  } catch (err) {
      return res.status(500).json({ code: 500, message: 'Internal Server Error' });
  }
});

// 获取用户信息
app.get('/admin/acl/index/info', (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) {
        res.status(403).json({ code: 403, message: 'Invalid token' });
      } else {
        res.json({ code: 200, data: { username: user.username } });
      }
    });
  } else {
    res.status(401).json({ code: 401, message: 'No token provided' });
  }
});

// 退出登录
app.post('/admin/acl/index/logout', (req, res) => {
  res.json({ code: 200, message: 'Logged out successfully' });
});

// 获取全部的职位接口
app.get('/admin/acl/role/', async (req, res) => {
  const { page = 1, limit = 10, roleName } = req.query;
  const startIndex = (page - 1) * limit;
  let query = 'SELECT * FROM roles';
  const values = [];

  if (roleName) {
    query += ' WHERE name ILIKE $1';
    values.push(`%${roleName}%`);
  }

  query += ' ORDER BY id LIMIT $2 OFFSET $3';
  values.push(limit, startIndex);

  try {
    const result = await pool.query(query, values);
    res.json({ code: 200, data: result.rows, total: result.rowCount });
  } catch (err) {
    res.status(500).json({ code: 500, message: 'Internal Server Error' });
  }
});

// 新增岗位的接口
app.post('/admin/acl/role/save', async (req, res) => {
  const { name, description } = req.body;
  const query = 'INSERT INTO roles (name, description) VALUES ($1, $2) RETURNING *';

  try {
    const result = await pool.query(query, [name, description]);
    res.status(201).json({ code: 200, message: 'Role created successfully', data: result.rows[0] });
  } catch (err) {
    res.status(500).json({ code: 500, message: 'Internal Server Error' });
  }
});

// 更新已有的职位
app.put('/admin/acl/role/update', async (req, res) => {
  const { id, name, description } = req.body;
  const query = 'UPDATE roles SET name = $1, description = $2 WHERE id = $3 RETURNING *';

  try {
    const result = await pool.query(query, [name, description, id]);
    if (result.rows.length > 0) {
      res.json({ code: 200, message: 'Role updated successfully', data: result.rows[0] });
    } else {
      res.status(404).json({ code: 404, message: 'Role not found' });
    }
  } catch (err) {
    res.status(500).json({ code: 500, message: 'Internal Server Error' });
  }
});

// 删除已有的职位
app.delete('/admin/acl/role/remove/:roleId', async (req, res) => {
  const { roleId } = req.params;
  const query = 'DELETE FROM roles WHERE id = $1';

  try {
    const result = await pool.query(query, [roleId]);
    if (result.rowCount > 0) {
      res.json({ code: 200, message: 'Role removed successfully' });
    } else {
      res.status(404).json({ code: 404, message: 'Role not found' });
    }
  } catch (err) {
    res.status(500).json({ code: 500, message: 'Internal Server Error' });
  }
});

// 权限管理接口
app.get('/admin/acl/permission/toAssign/', async (req, res) => {
  const { roleId } = req.query;
  // Fetch permissions from database for the specific roleId
  // Assuming a table called permissions exists
  const query = 'SELECT * FROM permissions WHERE role_id = $1';
  try {
    const result = await pool.query(query, [roleId]);
    res.json({ code: 200, data: result.rows });
  } catch (err) {
    res.status(500).json({ code: 500, message: 'Internal Server Error' });
  }
});

// 给相应的职位分配权限
app.post('/admin/acl/permission/doAssign/', async (req, res) => {
  const { roleId, permissionId } = req.body; // 从body获取参数

  const query = 'INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)';
  try {
    await pool.query(query, [roleId, permissionId]);
    res.json({ code: 200, message: 'Permission assigned successfully' });
  } catch (err) {
    res.status(500).json({ code: 500, message: 'Internal Server Error' });
  }
});

// 获取宿舍信息
app.get('/admin/acl/dormitory/', async (req, res) => {
  const { page = 1, limit = 10 } = req.query;
  const startIndex = (page - 1) * limit;

  try {
    const result = await pool.query('SELECT * FROM dormitories ORDER BY id LIMIT $1 OFFSET $2', [limit, startIndex]);
    res.json({ code: 200, data: result.rows });
  } catch (error) {
    res.status(500).json({ code: 500, message: 'Internal Server Error' });
  }
});

// 获取全部已有用户账号信息
app.get('/admin/acl/user/', async (req, res) => {
  const { page = 1, limit = 10, username } = req.query;
  const startIndex = (page - 1) * limit;
  let query = 'SELECT * FROM users';
  const values = [];

  if (username) {
    query += ' WHERE username ILIKE $1';
    values.push(`%${username}%`);
  }

  query += ' ORDER BY id LIMIT $2 OFFSET $3';
  values.push(limit, startIndex);

  try {
    const result = await pool.query(query, values);
    res.json({ code: 200, data: result.rows, total: result.rowCount });
  } catch (err) {
    res.status(500).json({ code: 500, message: 'Internal Server Error' });
  }
});

// 添加一个新的用户账号
app.post('/admin/acl/user/save', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const query = 'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *';
  
  try {
    const result = await pool.query(query, [username, hashedPassword]);
    res.status(201).json({ code: 200, message: 'User created successfully', data: result.rows[0] });
  } catch (err) {
    res.status(500).json({ code: 500, message: 'Internal Server Error' });
  }
});

// 更新已有的用户账号
app.put('/admin/acl/user/update', async (req, res) => {
  const { id, username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const query = 'UPDATE users SET username = $1, password = $2 WHERE id = $3 RETURNING *';
  
  try {
    const result = await pool.query(query, [username, hashedPassword, id]);
    if (result.rows.length > 0) {
      res.json({ code: 200, message: 'User updated successfully', data: result.rows[0] });
    } else {
      res.status(404).json({ code: 404, message: 'User not found' });
    }
  } catch (err) {
    res.status(500).json({ code: 500, message: 'Internal Server Error' });
  }
});

// 获取用户坐标信息
app.get('/api/user/coordinates', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, email, longitude, latitude FROM users;'); // 根据实际情况修改查询语句
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ code: 500, message: 'Internal Server Error' });
  }
});

// 获取全部职位,当前账号拥有的职位接口
app.get('/admin/acl/user/toAssign/', async (req, res) => {
  const { userId } = req.query;
  const userRoles = await pool.query('SELECT roles.* FROM roles JOIN user_roles ON roles.id = user_roles.role_id WHERE user_roles.user_id = $1', [userId]);
  res.json({ code: 200, data: userRoles.rows });
});

// 给已有的用户分配角色接口
app.post('/admin/acl/user/doAssignRole', async (req, res) => {
  const { userId, roleId } = req.body;
  
  const user = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
  if (user.rows.length > 0) {
    const roleCheck = await pool.query('SELECT * FROM roles WHERE id = $1', [roleId]);
    if (roleCheck.rows.length > 0) {
      await pool.query('INSERT INTO user_roles(user_id, role_id) VALUES ($1, $2)', [userId, roleId]);
      res.json({ code: 200, message: 'Role assigned successfully' });
    } else {
      res.status(404).json({ code: 404, message: 'Role not found' });
    }
  } else {
    res.status(404).json({ code: 404, message: 'User not found' });
  }
});

// 删除某个账号
app.delete('/admin/acl/user/remove/:userId', async (req, res) => {
  const { userId } = req.params;
  const query = 'DELETE FROM users WHERE id = $1';
  
  try {
    const result = await pool.query(query, [userId]);
    if (result.rowCount > 0) {
      res.json({ code: 200, message: 'User removed successfully' });
    } else {
      res.status(404).json({ code: 404, message: 'User not found' });
    }
  } catch (err) {
    res.status(500).json({ code: 500, message: 'Internal Server Error' });
  }
});

// 批量删除的接口
app.delete('/admin/acl/user/batchRemove', async (req, res) => {
  const { idList } = req.body;
  const promises = idList.map(id => pool.query('DELETE FROM users WHERE id = $1', [id]));
  
  try {
    await Promise.all(promises);
    res.json({ code: 200, message: 'Users removed successfully' });
  } catch (error) {
    res.status(500).json({ code: 500, message: 'Internal Server Error' });
  }
});

// 根路由（测试）
app.get('/', (req, res) => {
    res.send('Welcome to my backend service!');
});

// 启动服务器
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});