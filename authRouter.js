const Router = require('express')
const controller = require('./authController')
const {check} = require('express-validator')
const authMiddleware = require('./middleware/authMiddleware')
const rolesMiddleware = require('./middleware/roleMiddleware')

const router = new Router()

router.post('/registration', [
    check('username', 'Empty user name.').notEmpty(),
    check('password', 'Incorrect password.').notEmpty().isLength({min: 4})
], controller.registration)
router.post('/login', controller.login)
router.get('/users', authMiddleware, rolesMiddleware(['ADMIN']), controller.getUsers)

module.exports = router