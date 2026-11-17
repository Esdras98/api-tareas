// 1. IMPORTACIÓN DE MÓDULOS
const express = require('express');
const fs = require('fs').promises; // Módulo nativo fs con promesas para NO bloquear el Event Loop
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// 2. CONFIGURACIÓN INICIAL DEL SERVIDOR
const app = express();
const PORT = 3000;
const SECRET_KEY = 'mi_clave_secreta_super_segura'; // Clave para firmar los tokens JWT

// Rutas absolutas hacia nuestros archivos JSON
const TAREAS_FILE = path.join(__dirname, 'tareas.json');
const USUARIOS_FILE = path.join(__dirname, 'usuarios.json');

// 3. MIDDLEWARE PARA PARSEAR JSON (Debe ir siempre antes de las rutas)
app.use(express.json());

// =========================================================================
// 4. FUNCIONES AUXILIARES ASÍNCRONAS (Lectura y escritura sin bloqueos)
// =========================================================================

async function leerArchivo(ruta) {
  try {
    const contenido = await fs.readFile(ruta, 'utf8');
    return JSON.parse(contenido);
  } catch (error) {
    // Si el archivo no existe, lo crea vacío automáticamente
    if (error.code === 'ENOENT') {
      await fs.writeFile(ruta, '[]', 'utf8');
      return [];
    }
    throw error;
  }
}

async function guardarArchivo(ruta, datos) {
  // null, 2 hace que el JSON se guarde ordenado y legible con sangrías
  await fs.writeFile(ruta, JSON.stringify(datos, null, 2), 'utf8');
}

// =========================================================================
// 5. MIDDLEWARES PERSONALIZADOS (Autenticación y Validación)
// =========================================================================

// Verifica que el usuario envíe un Token JWT válido en la cabecera Authorization
function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  // Extrae el token ya sea que venga como "Bearer <token>" o solo "<token>"
  const token = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.split(' ')[1]
    : authHeader;

  if (!token) {
    const err = new Error('Acceso denegado. Debes iniciar sesión y enviar un token.');
    err.status = 401;
    return next(err); // Envía el error al middleware global
  }

  jwt.verify(token, SECRET_KEY, (error, usuarioDecodificado) => {
    if (error) {
      const err = new Error('Token inválido o expirado.');
      err.status = 403;
      return next(err);
    }
    req.user = usuarioDecodificado; // Guarda los datos del usuario en la petición
    next(); // Permite continuar hacia la ruta
  });
}

// Valida que al crear o editar una tarea se envíen título y descripción
function validarTarea(req, res, next) {
  const { titulo, descripcion } = req.body;

  if (!titulo || typeof titulo !== 'string' || titulo.trim() === '') {
    const err = new Error('El campo "titulo" es obligatorio.');
    err.status = 400;
    return next(err);
  }

  if (!descripcion || typeof descripcion !== 'string' || descripcion.trim() === '') {
    const err = new Error('El campo "descripcion" es obligatorio.');
    err.status = 400;
    return next(err);
  }

  next();
}

// =========================================================================
// 6. RUTAS DE AUTENTICACIÓN (Registro e Inicio de Sesión)
// =========================================================================

// POST /register -> Registra un nuevo usuario encriptando su contraseña
app.post('/register', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      const err = new Error('Debes enviar username y password.');
      err.status = 400;
      return next(err);
    }

    const usuarios = await leerArchivo(USUARIOS_FILE);

    // Verificar si el usuario ya existe
    if (usuarios.some(u => u.username === username)) {
      const err = new Error('El usuario ya existe.');
      err.status = 409;
      return next(err);
    }

    // Encriptar contraseña con bcryptjs (10 rondas de sal)
    const passwordEncriptada = await bcrypt.hash(password, 10);

    const nuevoUsuario = {
      id: Date.now(),
      username,
      password: passwordEncriptada
    };

    usuarios.push(nuevoUsuario);
    await guardarArchivo(USUARIOS_FILE, usuarios);

    console.log(`[AUTH] Nuevo usuario registrado: ${username}`);
    res.status(201).json({
      mensaje: 'Usuario registrado exitosamente',
      usuario: { id: nuevoUsuario.id, username: nuevoUsuario.username }
    });
  } catch (error) {
    next(error);
  }
});

// POST /login -> Verifica credenciales y entrega un Token JWT
app.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const usuarios = await leerArchivo(USUARIOS_FILE);

    const usuario = usuarios.find(u => u.username === username);
    if (!usuario) {
      const err = new Error('Usuario o contraseña incorrectos.');
      err.status = 401;
      return next(err);
    }

    // Comparar contraseña ingresada con la contraseña encriptada
    const esValida = await bcrypt.compare(password, usuario.password);
    if (!esValida) {
      const err = new Error('Usuario o contraseña incorrectos.');
      err.status = 401;
      return next(err);
    }

    // Generar Token con vigencia de 1 hora
    const token = jwt.sign(
      { id: usuario.id, username: usuario.username },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    console.log(`[AUTH] Sesión iniciada por: ${username}`);
    res.json({
      mensaje: 'Inicio de sesión exitoso',
      token: token
    });
  } catch (error) {
    next(error);
  }
});

// =========================================================================
// 7. RUTAS CRUD DE TAREAS (Protegidas con autenticarToken)
// =========================================================================

// GET /tareas -> Obtener todas las tareas
app.get('/tareas', autenticarToken, async (req, res, next) => {
  try {
    const tareas = await leerArchivo(TAREAS_FILE);
    res.json(tareas);
  } catch (error) {
    next(error);
  }
});

// POST /tareas -> Crear una nueva tarea
app.post('/tareas', autenticarToken, validarTarea, async (req, res, next) => {
  try {
    const { titulo, descripcion } = req.body;
    const tareas = await leerArchivo(TAREAS_FILE);

    const nuevaTarea = {
      id: Date.now(), // Genera un ID numérico único basado en la hora actual
      titulo: titulo.trim(),
      descripcion: descripcion.trim(),
      completada: false,
      creadaPor: req.user.username
    };

    tareas.push(nuevaTarea);
    await guardarArchivo(TAREAS_FILE, tareas);

    console.log(`[TAREAS] Tarea creada con ID: ${nuevaTarea.id}`);
    res.status(201).json({
      mensaje: 'Tarea creada exitosamente',
      tarea: nuevaTarea
    });
  } catch (error) {
    next(error);
  }
});

// PUT /tareas/:id -> Actualizar una tarea por su ID
app.put('/tareas/:id', autenticarToken, validarTarea, async (req, res, next) => {
  try {
    const idBuscado = parseInt(req.params.id);
    const { titulo, descripcion, completada } = req.body;
    const tareas = await leerArchivo(TAREAS_FILE);

    const indice = tareas.findIndex(t => t.id === idBuscado);
    if (indice === -1) {
      const err = new Error(`No se encontró ninguna tarea con el ID ${idBuscado}`);
      err.status = 404;
      return next(err);
    }

    tareas[indice] = {
      ...tareas[indice],
      titulo: titulo.trim(),
      descripcion: descripcion.trim(),
      completada: completada !== undefined ? Boolean(completada) : tareas[indice].completada
    };

    await guardarArchivo(TAREAS_FILE, tareas);

    console.log(`[TAREAS] Tarea actualizada ID: ${idBuscado}`);
    res.json({
      mensaje: 'Tarea actualizada exitosamente',
      tarea: tareas[indice]
    });
  } catch (error) {
    next(error);
  }
});

// DELETE /tareas/:id -> Eliminar una tarea por su ID
app.delete('/tareas/:id', autenticarToken, async (req, res, next) => {
  try {
    const idBuscado = parseInt(req.params.id);
    const tareas = await leerArchivo(TAREAS_FILE);

    const indice = tareas.findIndex(t => t.id === idBuscado);
    if (indice === -1) {
      const err = new Error(`No se encontró ninguna tarea con el ID ${idBuscado}`);
      err.status = 404;
      return next(err);
    }

    const tareaEliminada = tareas.splice(indice, 1)[0];
    await guardarArchivo(TAREAS_FILE, tareas);

    console.log(`[TAREAS] Tarea eliminada ID: ${idBuscado}`);
    res.json({
      mensaje: 'Tarea eliminada exitosamente',
      tarea: tareaEliminada
    });
  } catch (error) {
    next(error);
  }
});

// =========================================================================
// 8. MANEJO DE ERRORES Y ARRANQUE DEL SERVIDOR
// =========================================================================

// Middleware para rutas inexistentes (404)
app.use((req, res, next) => {
  const err = new Error(`La ruta ${req.method} ${req.originalUrl} no existe en esta API.`);
  err.status = 404;
  next(err);
});

// Middleware personalizado centralizado para manejo de errores
app.use((err, req, res, next) => {
  const estado = err.status || 500;
  console.error(`[ERROR ${estado}]: ${err.message}`);
  res.status(estado).json({
    error: true,
    status: estado,
    mensaje: err.message || 'Error interno del servidor'
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo exitosamente en http://localhost:${PORT}`);
});