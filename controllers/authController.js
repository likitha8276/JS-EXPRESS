const usersDB = {
    users: require("../models/users.json"),
    setUsers: function(data) { this.users = data }
};

const fsPromises = require('fs').promises;
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();  // ✅ Make sure .env is correctly configured

const handleLogin = async (req, res) => {
    const { username, password } = req.body;

    // ✅ 1. Validate input
    if (!username || !password) {
        return res.status(400).json({ "message": "Username and password are required." });
    }

    // ✅ 2. Find user
    const foundUser = usersDB.users.find(user => user.username === username);
    if (!foundUser) {
        return res.sendStatus(401); // Unauthorized
    }

    // ✅ 3. Compare password
    const match = await bcrypt.compare(password, foundUser.password);
    const roles = Object.values(foundUser.roles || {});

    if (match) {
        // ✅ 4. Generate tokens
        const accessToken = jwt.sign(
            {
                userInfo: {
                    username: foundUser.username,
                    roles: roles
                }
            },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '120s' }
        );

        const refreshToken = jwt.sign(
            { username: foundUser.username },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: '1d' }
        );

        // ✅ 5. Save refresh token
        const otherUsers = usersDB.users.filter(user => user.username !== foundUser.username);
        const currentUser = { ...foundUser, refreshToken };
        usersDB.setUsers([...otherUsers, currentUser]);

        try {
            await fsPromises.writeFile(
                path.join(__dirname, '..', 'models', 'users.json'),
                JSON.stringify(usersDB.users, null, 2)
            );
        } catch (err) {
            console.error("Error saving refreshToken to users.json:", err);
            return res.status(500).json({ message: "Server error while saving session." });
        }

        // ✅ 6. Send tokens
        res.cookie('jwt', refreshToken, {
            httpOnly: true,
            sameSite: 'None',
            secure: true
        });

        res.json({ accessToken });

    } else {
        res.sendStatus(401); // Unauthorized
    }
};

module.exports = { handleLogin };
