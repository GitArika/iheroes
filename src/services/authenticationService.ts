import bcrypt from 'bcrypt'

import { ISignin, ISignup } from '../interfaces/authentication'
import { BusinessError } from '../controllers/error'
import { User } from '../data-mapper/users'
import { UserModel } from '../models/usersModel'

class AuthenticationService {
    public async signup(signup: ISignup) {
        const foundUser = await UserModel.findOne({
            where: {
                email: signup.email,
            },
        })

        if (foundUser) {
            throw new BusinessError('Something went wrong. Please try again later.', 400)
        }

        const user = new User({ ...signup, password_hash: '' })

        await user.hash()
        const savedUser = await user.save()

        return savedUser
    }

    public async signin(signin: ISignin) {
        const foundUser = await UserModel.findOne({
            where: {
                email: signin.email,
            },
        })
        if (!foundUser) {
            throw new BusinessError('Invalid credentials.', 401)
        }

        const passwordMatch = await bcrypt.compare(
            signin.password,
            foundUser.dataValues.password_hash,
        )

        if (!passwordMatch) {
            throw new BusinessError('Invalid credentials.', 401)
        }

        delete foundUser.dataValues.password_hash

        return foundUser
    }
}

export default new AuthenticationService()
