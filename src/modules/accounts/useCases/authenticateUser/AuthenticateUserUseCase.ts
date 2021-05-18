
import { compare } from "bcrypt";
import { inject, injectable } from "tsyringe";
import { sign } from "jsonwebtoken";

import { IUsersRepository } from "../../repositories/IUsersRepository";
import { AppError } from "../../../../errors/AppError";


interface IRequest {
    email: string;
    password: string;
}

interface IResponse {
    user: {
        name: string;
        email: string;
    };
    token: string;
}

@injectable()
class AuthenticateUserUseCase {
    constructor(
        @inject("UsersRepository")
        private usersRepository: IUsersRepository
    ) {};

    async execute({ email, password }: IRequest): Promise<IResponse>{
        const user = await this.usersRepository.findByEmail(email);

        if (!user) {
            throw new AppError("Email or passaword incorrect!");
        }

        const passawordMatch = await compare(password, user.password);

        if (!passawordMatch) {
            throw new AppError("Email or passaword incorrect!");
        }

        const token = sign({}, "2113838409c2f5725ca1cb3d50a10885", {
            subject: user.id,
            expiresIn: "1d",
        });

        const tokenReturn: IResponse = {
            token,
            user: {
                name: user.name,
                email: user.email,
            }
        }

        return tokenReturn;
    }
}

export { AuthenticateUserUseCase }