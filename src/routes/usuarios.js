const express = require('express')
const router = express.Router()
const Usuario = require('../models/usuario')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const CONTRASENA_DEFAULT = 'Password123'

const nombreV = {
  permitido: 'Letras mayúsculas y minúsculas; números; guion bajo; guion medio, punto.', 
  min: 4, max: 16, regEx: /^[a-z,A-Z, 0-9,_,-,\.]{4,16}$/, 
  mensajeError: function() { return `Formato incorrecto en el nombre de usuario: 
    ${this.permitido}; min: ${this.min}; máx: ${this.max}`}};
const contrasenaV = {
  permitido: 'Letras mayúsculas y minúsculas; números; símbolos',
  min: 8, max: 255, regEx: /^.{8,254}$/, 
  mensajeError: function() {return `Formato incorrecto en la contraseña: 
    ${this.permitido}; min: ${this.min}; máx: ${this.max}`}
}

// VARIABLE PARA ALMACENAR HASH DE CONTRASEÑA
let hp

// CREAR HASH DE CONTRASEÑA
async function hashContrasena(contrasena) {
  hp = await bcrypt.hash(contrasena, 10)
}

function autenticarToken(req, res, next) {
  const encabezadoAut = req.headers['authorization']

  const token = encabezadoAut && encabezadoAut.split(' ')[1]
  
  if(token == null) return res.status(201).json({ autorizado: false })

  jwt.verify(token, process.env.JWT_KEY, (err, usuario)=>{
      if(err) return res.status(201).json({ autorizado: false, motivo: err.message })

      // USUARIO QUE SOLICITA LA FUNCIONALIDAD A LA API
      res.usuarioSolicitante = usuario
      next()
  })
}

// COMPARA LA CONTRASEÑA CONTRA EL HASH GUARDADO
async function compararContrasena(contrasena, hash) {
  const resultado = await bcrypt.compare(contrasena, hash)
  return resultado
}

// LISTAR TODOS LOS USUARIOS
router.get('/', async (req, res)=>{
  try {
    const usuarios = await Usuario.find()
    res.json(usuarios)
  } catch (error) {
    res.status(500).json({error: 2, mensaje: error.message})
  }
})

// LISTAR UN ÚNICO USUARIO POR ID
router.get('/:id', obtenerUsuarioID, async (req, res)=>{
  res.json(res.usuario)
})

// LISTAR UN ÚNICO USUARIO POR NOMBRE DE USUARIO
router.get('/nombre/:nombre', obtenerUsuarioNombre, async (req, res)=>{
  res.json(res.usuario)
})

// VALIDAR CONTRASEÑA
router.post('/validarcontrasena/:nombre', obtenerUsuarioNombre, async (req, res)=>{
  const resultado = await compararContrasena(req.body.contrasena, res.usuario.contrasena)

  let tokenAcceso

  // SI LA CONTRASEÑA ES VÁLIDA, GENERAR TOKEN DE ACCESO
  if(resultado){
    tokenAcceso = generarTokenAcceso(res.usuario)
  }

  res.status(201).json({ validado: resultado, 
    tokenAcceso: tokenAcceso, 
    idUsuario: res.usuario._id,
    nivel: res.usuario.tipo })
})

// FUNCIÓN PARA VALIDAR EL NIVEL DE ACCESO DE UN USUARIO SOLICITANTE
function validarNivel(usuario, nivelRequerido) {
  const resultado = {
    autorizado: false, 
    motivo: 'Nivel de acceso insuficiente', 
    nivelRequerido: nivelRequerido, 
    nivel: usuario.tipo
  }
  if(usuario.tipo <= nivelRequerido) {    
    resultado.autorizado = true
    resultado.motivo = 'Autorizado'
  }

  return resultado
}

// CREAR USUARIO
router.post('/crearusuario', autenticarToken, async (req, res)=>{

  // VALIDAR NIVEL DE ACCESO (2)
  const validacion = validarNivel(res.usuarioSolicitante, 2)
  if(!validacion.autorizado) return res.status(200).json(validacion);

  // SI LA CONTRASENA ESTA EN BLANCO, USAR CONTRASENA POR DEFECTO
  if(req.body.contrasena !== '' ) {
    // VALIDAR CONTRASEÑA
    if(!contrasenaV.regEx.test(req.body.contrasena)){
      return res.status(200).json({ error: 1, mensaje: contrasenaV.mensajeError() }); 
    }
  } 
  
  // VALIDAR NOMBRE DE USUARIO
  if(!nombreV.regEx.test(req.body.nombre)){
    return res.status(200).json({ error: 1, mensaje: nombreV.mensajeError() }); 
  } 

  // SI LA CONTRASENA ESTA EN BLANCO, USAR CONTRASENA POR DEFECTO
  if(req.body.contrasena === '' ) {
    hashContrasena(CONTRASENA_DEFAULT)
  } else await hashContrasena(req.body.contrasena)
  
  const usuario = new Usuario({
    nombre: req.body.nombre,
    contrasena: hp,
    tipo: req.body.tipo,
    nombreCompleto: req.body.nombreCompleto,
    tokenRefresco: generarTokenRefresco({ 
      nombre: req.body.nombre, 
      contrasena: hp, 
      tipo: req.body.tipo, 
      nombreCompleto: req.body.nombreCompleto }),
    activo: true
  })
 
  try {
    const nuevoUsuario = await usuario.save()
    res.status(201).json(nuevoUsuario)
  } catch (error) {
    res.status(200).json({ error: 2, mensaje: error.message })
  }

  //return res.status(200).json({ mensaje: 'Usuario creado correctamente' })
})

// HABILITAR/DESHABILITAR UN USUARIO POR NOMBRE
router.post('/habilitacion/:nombre', autenticarToken, obtenerUsuarioNombre, async (req, res)=> {
  // VALIDAR NIVEL DE ACCESO (2)
  const validacion = validarNivel(res.usuarioSolicitante, 2)
  if(!validacion.autorizado) return res.status(200).json(validacion);
  
  res.usuario.activo = !res.usuario.activo
  try {
    
    const usuarioActualizado = await res.usuario.save()
    return res.json(usuarioActualizado)
  } catch (error) {
    return res.status(200).json({ error: 2, mensaje: error.message })
  }
})

// CAMBIAR CONTRASEÑA
router.post('/cambiarcontrasena/:nombre', autenticarToken, obtenerUsuarioNombre, async (req, res) => {
  // VERIFICAR SI LA NUEVA CONTRASEÑA COINCIDE CON SU DUPLICADO
  const duplicado = req.body.nuevaContrasena === req.body.duplicadoNuevaContrasena
  if(!duplicado) {
    return res.status(201).json({ error: 1, mensaje: `La nueva contraseña y su duplicado no coinciden.` })
  }
  
  const resultado = await compararContrasena(req.body.contrasenaActual, res.usuario.contrasena)
  if(resultado) {
    await hashContrasena(req.body.nuevaContrasena)
    try {
      res.usuario.contrasena = hp
      res.usuario.tokenRefresco = generarTokenRefresco(res.usuario)
      const usuarioActualizado = await res.usuario.save()
      return res.json(usuarioActualizado)
    } catch (error) {
      return res.status(200).json({ error: 2, mensaje: error.message })
    }
  } else {
    return res.status(201).json({ error: 1, mensaje: 'La contraseña actual es incorrecta' })
  }
})

// MIDDLEWARE PARA OBTENER UN USUARIO POR NOMBRE
async function obtenerUsuarioNombre(req, res, next) {  

  let usuario

  try {
    
    usuario = await Usuario.findOne({ nombre: req.params.nombre })

    if(usuario == null){
      return res.status(404).json({ error: 1, mensaje: 'No se pudo encontrar el usuario'})
    }    
  } catch (error) {
    res.status(200).json({ error: 2, mensaje: error.message })
  }
  res.usuario = usuario
  next()
}

// MIDDLEWARE PARA OBTENER UN USUARIO POR ID
async function obtenerUsuarioID(req, res, next) {  

  // VALIDAR EL ID DE USUARIO  
  if(!esIDValida(req.params.id)) {    
    return res.status(200).json({ error: 1, mensaje: 'Parámetros inválidos'}); 
  }

  let usuario

  try {
    
    usuario = await Usuario.findById(req.params.id)
    if(usuario == null){
      return res.status(404).json({ error: 1, mensaje: 'No se pudo encontrar el usuario'})
    }
  } catch (error) {
    res.status(200).json({ mensaje: error.message })
  }

  res.usuario = usuario
  next()
}

// VALIDAR LONGITUD DE ID
function esIDValida(id) {  
  return id.length === 24
}

// GENERAR TOKEN DE ACCESO
function generarTokenAcceso(usuario) {
  return jwt.sign({
    nombre: usuario.nombre, 
    contrasena: usuario.contrasena, 
    tipo: usuario.tipo, 
    nombreCompleto: usuario.nombreCompleto
  }, process.env.JWT_KEY, { expiresIn: '10m'})
}

// GENERAR TOKEN DE REFRESCO
function generarTokenRefresco(usuario) {
  return jwt.sign({
    nombre: usuario.nombre, 
    contrasena: usuario.contrasena, 
    tipo: usuario.tipo, 
    nombreCompleto: usuario.nombreCompleto 
  }, process.env.JWT_REFRESH)
}

// OBTENER NUEVO TOKEN BASADO EN TOKEN DE REFRESCO
router.post('/token', (req, res)=> {
  const tokenRefresco = req.body.tokenRefresco
  if (tokenRefresco == null) return res.sendStatus(201).json({ autorizado: false, motivo: 'Sin token' })
  
  jwt.verify(tokenRefresco, process.env.JWT_REFRESH, (err, usuario)=>{
      if(err) return res.sendStatus(201).json({ autorizado: false, motivo: err.message})
      const tokenAcceso = generarTokenAcceso(usuario)
      res.json({ tokenAcceso: tokenAcceso })
  })
})


module.exports = router