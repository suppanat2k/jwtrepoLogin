const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();
require('./config/database').connect();
const User = require('./model/user')
const auth = require('./middleware/auth')

const app = express();
app.use(express.json());

app.post('/register', async (req, res) => {
    try {
        const {username, email, password } = req.body;
        if(!(email&&password)){
            return res.status(400).send("All input is required");
        }
        const oldUser = await User.findOne({email})
        if(oldUser){
            return res.status(409).send("User already exist");
        }

        encryptedPassword = await bcrypt.hash(password,10);
        const user = await User.create({
            username,
            email:email.toLowerCase(),
            password:encryptedPassword
        })

        const token = jwt.sign(
            { user_id: user._id, email },
            process.env.TOKEN_KEY,
            {
                expiresIn: "2h"
            }
        )

        user.token = token;
        res.status(201).json(user);

    } catch (error) {
        console.log(error);
    }

})

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!(email && password)) {
            return res.status(400).send("All input is required");
        }

        const user = await User.findOne({ email })

        if (user && (await bcrypt.compare(password, user.password))) {
            const token = jwt.sign(
                { user_id: user._id, email },
                process.env.TOKEN_KEY,
                {
                    expiresIn: "2h"
                }
            )

            user.token = token;
            res.setHeader('x-access-token', 'text/html');
            res.status(200).json(user);
        }

        res.status(400).send("Invalid Credentials");

    } catch (error) {
        console.log(error);
    }

})

app.post('/welcome',auth,(req,res)=>{
    res.status(200).send('Welcome!')
})

module.exports = app;