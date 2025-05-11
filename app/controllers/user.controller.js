// Controlador que responde a rutas públicas (accesibles sin autenticación)
export const allAccess = (req, res) => {
    res.status(200).send("Public Content."); // Responde con contenido público
};

// Controlador que responde a rutas accesibles solo para usuarios autenticados
export const userBoard = (req, res) => {
    res.status(200).send("User Content."); // Responde con contenido para usuarios comunes
};

// Controlador que responde a rutas exclusivas para administradores
export const adminBoard = (req, res) => {
    res.status(200).send("Admin Content."); // Responde con contenido para admins
};

// Controlador que responde a rutas exclusivas para moderadores
export const moderatorBoard = (req, res) => {
    res.status(200).send("Moderator Content."); // Responde con contenido para moderadores
};


