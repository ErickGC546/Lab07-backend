// Importamos el módulo 'jsonwebtoken' para trabajar con JWT
import jwt from "jsonwebtoken";

// Importamos los modelos y constantes definidos en la aplicación
import db from "../models/index.js";

// Importamos la configuración de autenticación (clave secreta)
import authConfig from "../config/auth.config.js";

// Extraemos los modelos 'User' y 'Role' del objeto 'db'
const { user: User, role: Role } = db;

/**
 * Middleware para verificar la validez del token JWT en las solicitudes entrantes.
 */
export const verifyToken = async (req, res, next) => {
    // Obtenemos el token del encabezado 'x-access-token' o 'authorization'
    const token = req.headers["x-access-token"] || req.headers["authorization"];

    // Si no se proporciona un token, respondemos con un error 403 (Prohibido)
    if (!token) {
        return res.status(403).json({ message: "¡No se proporcionó un token!" });
    }

    try {
        // Verificamos y decodificamos el token, eliminando el prefijo 'Bearer ' si existe
        const decoded = jwt.verify(token.replace("Bearer ", ""), authConfig.secret);

        // Almacenamos el ID del usuario decodificado en la solicitud para su uso posterior
        req.userId = decoded.id;

        // Buscamos al usuario en la base de datos utilizando el ID
        const user = await User.findByPk(req.userId);

        // Si no se encuentra el usuario, respondemos con un error 401 (No autorizado)
        if (!user) {
            return res.status(401).json({ message: "¡No autorizado!" });
        }

        // Si todo es correcto, pasamos al siguiente middleware
        next();
    } catch (err) {
        // Si ocurre un error al verificar el token, respondemos con un error 401
        return res.status(401).json({ message: "¡No autorizado!" });
    }
};

/**
 * Middleware para verificar si el usuario tiene el rol de 'admin'.
 */
export const isAdmin = async (req, res, next) => {
    try {
        // Buscamos al usuario en la base de datos utilizando el ID almacenado en la solicitud
        const user = await User.findByPk(req.userId);

        // Obtenemos los roles asociados al usuario
        const roles = await user.getRoles();

        // Verificamos si alguno de los roles del usuario es 'admin'
        const adminRole = roles.find((role) => role.name === "admin");

        // Si el usuario tiene el rol de 'admin', pasamos al siguiente middleware
        if (adminRole) {
            next();
            return;
        }

        // Si el usuario no tiene el rol de 'admin', respondemos con un error 403
        res.status(403).json({ message: "¡Se requiere el rol de administrador!" });
    } catch (error) {
        // Si ocurre un error, respondemos con un error 500 (Error interno del servidor)
        res.status(500).json({ message: error.message });
    }
};

/**
 * Middleware para verificar si el usuario tiene el rol de 'moderator'.
 */
export const isModerator = async (req, res, next) => {
    try {
        // Buscamos al usuario en la base de datos utilizando el ID almacenado en la solicitud
        const user = await User.findByPk(req.userId);

        // Obtenemos los roles asociados al usuario
        const roles = await user.getRoles();

        // Verificamos si alguno de los roles del usuario es 'moderator'
        const modRole = roles.find((role) => role.name === "moderator");

        // Si el usuario tiene el rol de 'moderator', pasamos al siguiente middleware
        if (modRole) {
            next();
            return;
        }

        // Si el usuario no tiene el rol de 'moderator', respondemos con un error 403
        res.status(403).json({ message: "¡Se requiere el rol de moderador!" });
    } catch (error) {
        // Si ocurre un error, respondemos con un error 500
        res.status(500).json({ message: error.message });
    }
};

/**
 * Middleware para verificar si el usuario tiene el rol de 'admin' o 'moderator'.
 */
export const isModeratorOrAdmin = async (req, res, next) => {
    try {
        // Buscamos al usuario en la base de datos utilizando el ID almacenado en la solicitud
        const user = await User.findByPk(req.userId);

        // Obtenemos los roles asociados al usuario
        const roles = await user.getRoles();

        // Verificamos si alguno de los roles del usuario es 'admin' o 'moderator'
        const hasRole = roles.some((role) => ["admin", "moderator"].includes(role.name));

        // Si el usuario tiene el rol requerido, pasamos al siguiente middleware
        if (hasRole) {
            next();
            return;
        }

        // Si el usuario no tiene los roles requeridos, respondemos con un error 403
        res.status(403).json({ message: "¡Se requiere el rol de moderador o administrador!" });
    } catch (error) {
        // Si ocurre un error, respondemos con un error 500
        res.status(500).json({ message: error.message });
    }
};
