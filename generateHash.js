const bcrypt = require('bcryptjs');

// 设置您要加密的密码
const passwords = [
    // 这里是举例密码为这些：
    'password6',
    'password7',
    'password8',
    'password9',
    'password10',
    'password11',
    'password12',
    'password13',
    'password14',
    'password15',
];

// 生成哈希并打印
passwords.forEach(async password => {
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(`原始密码: ${password}, 哈希: ${hashedPassword}`);
});