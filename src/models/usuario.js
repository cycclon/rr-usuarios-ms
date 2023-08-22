const mongoose = require('mongoose')

const esquemaUsuario = mongoose.Schema({
  nombre: {
    type: String,
    trim: true,
    required: true,
    index: {
      unique: true
    },
    lowercase: true,
    minlength: [4, "El nombre de usuario debe tener un mínimo de 4 caracteres"],
    maxlength: [16, "El nombre de usuario debe tener un máximo de 16 caracteres"]
  },
  contrasena: {
    type: String,
    required: true,
    minlength: [8, "La contraseña debe tener un mínimo de 8 caracteres."],
    maxlength: [64, "La contraseña debe tener un máximo de 64 caracteres."]
  },
  tipo: {
    type: Number,
    required: true
  },
  nombreCompleto: {
    type: String,
    required: true,
    minlength: [5, "El nombre completo debe tener un mínimo de 5 caracteres"],
    maxlength: [64, "El nombre completo debe tener un máximo de 64 caracteres"]
  },
  tokenRefresco: {
    type: String,
    required: [true, "Debe generar un token de refresco"]
  },
  activo: {
    type: Boolean,
    required: true
  }
}, { versionKey: false })

module.exports = mongoose.model('Usuario', esquemaUsuario)