const User = require('./models/User')
const Role = require('./models/Role')
const bcrypt = require('bcryptjs')
const {validationResult} = require('express-validator')
const jwt = require('jsonwebtoken')
const {secret} = require('./config')

const generateAccessToken = (id, roles) => {
    const payload = {
        id,
        roles
    }

    return jwt.sign(payload, secret, {expiresIn: '24h'})
}

class authController {
    async registration(req, res) {
        try {
            const errors = validationResult(req)
            if (!errors.isEmpty()) {
                return res.status(400).json({message: errors})
            }

            const {username, password} = req.body
            const candidate = await User.findOne({username})
            if (candidate) {
                return res.status(400).json({message: 'User already exist.'})
            }
            const salt = bcrypt.genSaltSync(10);
            const hashPassword = bcrypt.hashSync(password, salt)

            const userRole = await Role.findOne({value: 'USER'})

            const user = new User({username, password: hashPassword, roles: [userRole.value]})
            await user.save()
            return res.status(200).json({message: 'User save!'})
        } catch (e) {
            console.log(e)
            res.status(400).json({message: `Error ${e}`})
        }
    }

    async login(req, res) {
        try {

            const {username, password} = req.body
            const user = await User.findOne({username})

            if (!user) {
                return res.status(400).json({message: `${username} not found.`})
            }

            const validPassword = bcrypt.compareSync(password, user.password)

            if (!validPassword) {
                return res.status(400).json({message: 'Invalid password.'})
            }

            const token = generateAccessToken(user._id, user.roles)
            return res.json({token})

        } catch (e) {
            console.log(e)
            res.status(400).json({message: `Error ${e}`})
        }
    }

    async getUsers(req, res) {
        try {
            const users = await User.find()
            return res.json(users)
        } catch (e) {
            console.log(e)
            res.status(400).json({message: `Error ${e}`})
        }
    }
}

module.exports = new authController()