const express = require('express')
const router = express.Router()
const { crearUsuario, loginUser, misDatos } = require('../controllers/usersControllers')
const { protect } = require('../middleware/authMiddleware')

router.post('/', crearUsuario)
router.post('/login', loginUser)
router.get('/me', protect, misDatos)

module.exports = router