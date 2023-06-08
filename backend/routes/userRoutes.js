const express = require('express')
const router = express.Router()
const { crearUsuario, loginUser, misDatos } = require('../controllers/usersControllers')

router.post('/', crearUsuario)
router.post('/login', loginUser)
router.get('/me', misDatos)

module.exports = router