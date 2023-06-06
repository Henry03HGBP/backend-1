const mongoose = require('mongoose')

const tareaSchema = mongoose.Schema({
    texto: {
        type: String,
        required: [true, 'Por favor escribe el texto de la tarea']
    }
}, {
    timestamps: true
})

module.exports = mongoose.model('Tarea', tareaSchema)