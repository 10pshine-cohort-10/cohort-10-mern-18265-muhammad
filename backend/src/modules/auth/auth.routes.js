import express from "express";
import { registerUser, login, refreshAccessToken, logout } from "./auth.controller.js";
import { protect } from "../../middleware/auth.middleware.js";


const router = express.Router();


router.post("/register", registerUser);
router.post("/login", login);
router.post("/refresh", refreshAccessToken);
router.post("/logout", protect, logout);


export default router;