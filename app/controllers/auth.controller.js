// Importa el objeto de modelos (User, Role, etc.) desde la carpeta models 
import db from "../models/index.js";

// Importa la librería jsonwebtoken para generar tokens JWT
import jwt from "jsonwebtoken";

// Importa bcryptjs para encriptar y comparar contraseñas
import bcrypt from "bcryptjs";

// Importa la configuración del secreto JWT desde un archivo de configuración
import authConfig from "../config/auth.config.js";

// Extrae los modelos User y Role desde el objeto db
const { user: User, role: Role } = db;

// Controlador para el registro de usuarios
export const signup = async (req, res) => {
    try {
        const { username, email, password, roles } = req.body;

        const hashedPassword = await bcrypt.hash(password, 8);

        const user = await User.create({
            username,
            email,
            password: hashedPassword,
        });

        if (roles && roles.length > 0) {
            // Busca los roles especificados en la base de datos
            const foundRoles = await Role.findAll({
                where: {
                    name: roles, // roles es un array: ["admin"], ["moderator"], etc.
                },
            });

            // Asocia los roles encontrados al usuario
            await user.setRoles(foundRoles);
        } else {
            // Si no se especificaron roles, asigna el rol por defecto "user"
            const defaultRole = await Role.findOne({ where: { name: "user" } });
            await user.setRoles([defaultRole]);
        }

        res.status(201).json({ message: "User registered successfully!" });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// Controlador para el inicio de sesión
export const signin = async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await User.findOne({
            where: { username },
            include: {
                model: Role,
                as: "roles",
                through: { attributes: [] }, // opcional: omite datos de la tabla intermedia
            },
        });

        if (!user) {
            return res.status(404).json({ message: "User Not found." });
        }

        const passwordIsValid = await bcrypt.compare(password, user.password);

        if (!passwordIsValid) {
            return res.status(401).json({
                accessToken: null,
                message: "Invalid Password!",
            });
        }

        const token = jwt.sign({ id: user.id }, authConfig.secret, {
            expiresIn: 86400,
        });

        const authorities = user.roles.map(role => `ROLE_${role.name.toUpperCase()}`);

        res.status(200).json({
            id: user.id,
            username: user.username,
            email: user.email,
            roles: authorities,
            accessToken: token,
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};
