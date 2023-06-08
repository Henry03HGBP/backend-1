const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const asynchandler = require('express-async-handler')
const User = require('../models/userModel')

const crearUsuario = asynchandler(async (req, res) => {

    //desestructuramos el body
    const { name, email, password } = req.body

    //validamos la info
    if (!name || !email || !password) {
        res.status(400)
        throw new Error('Faltan datos')
    }

    //verificamos si existe el usuario
    const userExists = await User.findOne({ email })
    if (userExists) {
        res.status(400)
        throw new Error('Ese usuario ya existe')
    }

    //generamos la sal y el hash 
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    //creamos el usuario
    const user = await User.create({
        name,
        email,
        password: hashedPassword
    })

    //verificamos que se haya creado
    if (user) {
        res.status(201).json({
            _id: user.id,
            name: user.name,
            email: user.email
        })
    } else {
        res.status(400)
        throw new Error('Datos No Validos')
    }
})

const loginUser = asynchandler(async (req, res) => {

    //desestructuramos el body
    const { email, password } = req.body

    //buscamos el usuario
    const user = await User.findOne({ email })

    if (user && (await bcrypt.compare(password, user.password))) {
        res.status(200).json({
            _id: user.id,
            name: user.name,
            email: user.email,
            token: generateToken(user._id)
        })
    } else {
        res.status(400)
        throw new Error('Credenciales incorrectas')
    }
})

const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: '30d'
    })
}

const misDatos = asynchandler(async (req, res) => {
    res.status(200).json(req.user)
})

module.exports = {
    crearUsuario,
    loginUser,
    misDatos
}