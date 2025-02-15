import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js'

export const register = async(req, res)=>{
    const {name, email, password} = req.body; //извлекаем данные из тела запроса, которые отправляет клиент
    if(!name || !email || !password) {
        return res.json({success: false, message: 'Missing Details'})
    } // если данные отсутвтвуют отправляем ошибку с указание, что не хватает данных

    try {
        const existingUser = await userModel.findOne({email}) //ищет в базе данных пользователей с такой же почтой
        if(existingUser){
            return res.json({success: false, message: 'User already exists'})
        } //если пользователь с такой почтой существует возращаем ошибку
        const hashedPassword = await bcrypt.hash(password, 10); // хешируем пароль
        const user = new userModel({name, email, password: hashedPassword}); //создаем в базе данных пользователя передавая уже захешированный пароль
        await user.save(); //сохраняем в базе данных

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});// создаем токен в токен записываем ид пользователя секретный ключ, токен действителен в течении 7 дней
        res.cookie('token', token, {
            httpOnly: true, //делает недоступным куки для ДЖС
            secure: process.env.NODE_ENV === 'production', // если приложение запущено в проде куки доступны только в https
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', //в проде можно отправлять куки кросс-домено, в разработке локально в пределах одного домена
            maxAge: 7 * 24 * 60 * 60 * 1000
        })// устанавливаем куки с токеном
        //Sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome',
            text: 'Welcome test'
        }
        await transporter.sendMail(mailOptions)
        return res.json({success: true}) // возвращаем объект с успехом
    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

export const login = async(req, res) => {
    const {email, password} = req.body; //извлекаем данные из тела запроса, которые отправляет клиент
    if(!email || !password) {
        return res.json({success: false, message: 'Email and password are required'})
    } // если данные отсутвтвуют отправляем ошибку с указание, что не хватает данных
    try {
        const user = await userModel.findOne({email});//ищет в базе данных пользователей с такой же почтой
        if(!user){
            return res.json({success: false, message: 'Invalid email'})
        } //если нет пользователя с такой же почтой то возвращаем ошибку что нет такого пользователя
        const isMatch = await bcrypt.compare(password, user.password); //теперь проверяем через криптографию пароль и пароль пользователя 
        if(!isMatch){
            return res.json({success: false, message: 'Invalid password'})
        } //в случае несовпадения возвращаем ошибку
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});// создаем токен в токен записываем ид пользователя секретный ключ, токен действителен в течении 7 дней
        res.cookie('token', token, {
            httpOnly: true, //делает недоступным куки для ДЖС
            secure: process.env.NODE_ENV === 'production', // если приложение запущено в проде куки доступны только в https
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', //в проде можно отправлять куки кросс-домено, в разработке локально в пределах одного домена
            maxAge: 7 * 24 * 60 * 60 * 1000
        })// устанавливаем куки с токеном
        return res.json({success: true}) //возвращаем объект с успехом
    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

export const logout = async(req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true, //делает недоступным куки для ДЖС
            secure: process.env.NODE_ENV === 'production', // если приложение запущено в проде куки доступны только в https
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', //в проде можно отправлять куки кросс-домено, в разработке локально в пределах одного домена
        })//очищаем куки чтобы выйти из профиля

        return res.json({success:true, message: "Logged Out"})
    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

//Send Verification OTP to the User's Email
export const sendVerifyOtp = async(req, res)=>{
    try {
        const {userId} = req.body;
        const user = await userModel.findById(userId);
        if(user.isAccountVerified){
            return res.json({success: false, message: "Account Already verified"})
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;
        await user.save();
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Your OTP is ${otp}. Verify your account using this OTP.`
        }
        await transporter.sendMail(mailOptions)
        res.json({success:true, message: 'Verification OTP Sent on Email'})
    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

export const verifyEmail = async(req,res) => {
    const {userId, otp} = req.body; //извлекаем из тела запроса ИД и ОТП

    if(!userId || !otp) {
        return res.json({success: false, message: 'Missing Details'})
    } //если один из параметров отсутствует, возвращается ответ с ошибкой

    try {
        const user = await userModel.findById(userId); //поиск пользователя в базе данных
        if(!user) {
            return res.json({success: false, message: 'User not found'})
        } //если пользователен не найден возвращает ошибку
        if(user.verifyOtp === "" || user.verifyOtp !== otp) {
            return res.json({success: false, message: 'Invalid OTP'})
        } //если ОТП пустой или не совпадает с введенным ОТП возврашаем ошибку
        if(user.verifyOtpExpireAt < Date.now()){
            return res.json({success: false, message: 'OTP Expired'})
        } //если срок действия ОТП истек возвращаем ошибку
        user.isAccountVerified = true; // помечаем аккаунт как подтвержденный
        user.verifyOtp = '' // очищает ОТП
        user.verifyOtpExpireAt = 0 //сбрасываем время действия ОТП

        await user.save(); //сохраняем изменения в базе данных
        return res.json({success: true, message: 'Email verified successfully'})
    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

//Check if user is authenticated
export const isAuthenticated = async(req, res)=>{
    try {
        return res.json({success: true})
    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}

//Send Password Reset OTP 
export const sendResetOtp = async(req, res)=>{
    const {email} = req.body;
    if(!email){
        return res.json({success: false, message: 'Email is required'})
    }
    try {
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({success: false, message: 'User not found'})
        }
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;
        await user.save();
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Your OTP for reseting your password is ${otp}. Use this OTP to proceed with resetting your password.`
        }
        await transporter.sendMail(mailOptions);
        return res.json({success:true, message: 'OTP sent to your email'});
    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}

//Reset User Password
export const resetPassword = async(req, res)=>{
    const {email, otp, newPassword} = req.body; // извлекаем данные из боди
    if(!email || !otp || !newPassword){
        return res.json({success: false, message: 'Email, OTP and new password are required'})
    } //если что то не введено возвращаем ошибку
    try {
        const user = await userModel.findOne({email}) //ищем юзера по электронной почте
        if(!user){
            return res.json({success:false, message: 'User not found'}) //если не найден возвращаем ошибку
        }
        if(user.resetOtp === "" || user.resetOtp !== otp){
            return res.json({success: false, message: 'Invalid OTP'}) //если отп пустой или не совпадает с отправленным отп выбрасываем ошибку
        }
        if(user.resetOtpExpireAt < Date.now()){
            return res.json({success: false, message: 'OTP Expired'}) //если отп для сброса просрочен выбрасываем ошибку
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10); //хэшируем пароль
        user.password = hashedPassword; // у пользователя новый пароль
        user.resetOtp = ''; //обнуляем отп
        user.resetOtpExpireAt = 0; //обнуляем время
        await user.save() //записываем
        return res.json({success:true, message: 'Password has been reset successfully'});
    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}

