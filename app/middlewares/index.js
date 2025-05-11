// Importa todo lo exportado desde 'authJwt.js' como un objeto llamado 'authJwt'
// Esto incluye funciones como verifyToken, isAdmin, isModerator, etc., si están exportadas desde ese archivo
import * as authJwt from "./authJwt.js";

// Importa directamente las funciones 'checkDuplicateUsernameOrEmail' y 'checkRolesExisted'
// desde el archivo 'verifySignUp.js'. Estas funciones probablemente validan datos del usuario durante el registro.
import { checkDuplicateUsernameOrEmail, checkRolesExisted } from "./verifySignUp.js";

// Reexporta los middlewares importados para que puedan ser accedidos fácilmente desde otros archivos
// Por ejemplo, puedes hacer: `import { authJwt, checkDuplicateUsernameOrEmail } from "./middlewares/index.js"`
export { authJwt, checkDuplicateUsernameOrEmail, checkRolesExisted };
