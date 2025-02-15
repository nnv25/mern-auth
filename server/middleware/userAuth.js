import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
    const {token} = req.cookies //извлекаем токен из куки
    if(!token){
        return res.json({success: false, message: "Not Authorized. Login Again"}) //если токена нет прерываем функцию
    }
    try {
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET); //расшифровываем и проверяем токен
        if(tokenDecode.id){
            req.body.userId = tokenDecode.id //добавляем юзер ИД в рег боди для следующих обработчиков
        } else {
            return res.json({success: false, message: "Not Authorized. Login Again"})
        }

        next() //передаем управление следующему обработчику
    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

export default userAuth;