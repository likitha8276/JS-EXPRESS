const bcrypt = require('bcrypt');

const hashPassword = async (password) => {
  try {
    const hashed = await bcrypt.hash(password, 10);
    console.log(`Plain: ${password}`);
    console.log(`Hash: ${hashed}`);
  } catch (err) {
    console.error('Error hashing password:', err);
  }
};
hashPassword('yourpassword123');
