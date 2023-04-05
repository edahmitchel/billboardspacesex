const { buildSchema } = require("graphql");
module.exports = buildSchema(`
type User {
    _id: ID!
    email: String!
    password: String!
    username: String!
    
}
type AuthData {
    user:User!
    token:String!
}
input UserInputData {
    email: String!
    username: String!
    pass: String!
}

 
type RootQuery {
    login(email:String!,pass:String!):AuthData!
}

type RootMutation{
    createUser(userInput:UserInputData):User!
}
schema{
    query:RootQuery,
    mutation:RootMutation
}
`);
