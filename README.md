# IHeroes API v1.0.0

<p align="center">
  <img alt="GitHub language count" src="https://img.shields.io/github/languages/count/ritecsuy-ariel/iheroes-backend?color=%2304D361">

  <img alt="License" src="https://img.shields.io/badge/license-MIT-%2304D361">

  <a href="https://github.com/ritecsuy-ariel/iheroes-backend/stargazers">
    <img alt="Stargazers" src="https://img.shields.io/github/stars/ritecsuy-ariel/iheroes-backend?style=social">
  </a>
</p>

API incrível para demonstração de habilidades técnicas como desenvolvedor backend. 

Contém rotas HTTP para o gerenciamento completo de super heróis e combate de ameaças ao redor do mundo.

A lógica da aplicação conecta o servidor ao socket.io que dispara ameaças a cada 30 segundos.

Para resolver a ameaça, essa aplicação considera a latitude e longitude de cada herói, enviando o herói mais próximo e com nível adequado para cada tipo de ameaça.

# Features Incluídas

- Autenticação e cadastro ✅

- CRUD de heróis ✅

- Alocação de heróis ✅

- Histórico de ameaças ✅

- Alocação de heróis inteligente ✅

# Tecnologias Utilizadas

- Docker
- Node.js
- Express
- Cors
- Jsonwebtoken
- Postgres
- MongoDB
- Node-schedule

# Pré Requisitos

O ambiente do projeto está dockerizado, portanto, instale antes de prosseguir, [link de referencia](https://www.docker.com/).

# Sobre o Docker

A aplicação utiliza as imagens `postgres` e `mongodb` diretamente do dockerhub e a imagem `app` criada através do arquivo `Dockerfile`.

A imagem `app` tem multiplos passos de criação, separando a responsabilidade de `build` e execução, melhorando aspectos de tamanho e performance da imagem construída. 

## Iniciando a aplicação

Para iniciar a aplicação na porta 3333, executado com o comando:

```sh
    docker-compose up
```

## Testes

Os testes de aplicação podem ser realizados diretamente no container, execute o comando:

```sh
    docker-compose run app npm test
```

# Estrutura da aplicação

Todo código fonte da aplicação está mantido em `src`.

A aplicação utiliza uma chave `secret.key` para assinar o JWT durante a autenticação do usuário.

# Design Patterns

[Chain of Responsibility](https://refactoring.guru/design-patterns/chain-of-responsibility) é um padrão de design comportamental que permite passar solicitações ao longo de uma cadeia de manipuladores. Ao receber uma solicitação, cada manipulador decide processá-la ou passá-la para o próximo manipulador na cadeia.

[Observer](https://refactoring.guru/design-patterns/observer) é um padrão de design comportamental que permite definir um mecanismo de assinatura para notificar vários objetos sobre quaisquer eventos que aconteçam com o objeto que eles estão observando.

[Builder](https://refactoring.guru/design-patterns/builder) é um padrão de design criacional que permite construir objetos complexos passo a passo. O padrão permite produzir diferentes tipos e representações de um objeto usando o mesmo código de construção.

[Singleton](https://refactoring.guru/design-patterns/singleton) é um padrão de design criacional que permite garantir que uma classe tenha apenas uma instância, ao mesmo tempo que fornece um ponto de acesso global para essa instância.

[Single responsibility principle](https://en.wikipedia.org/wiki/Single_responsibility_principle) cada classe deveria ter apenas uma responsabilidade

[Open-closed principle](https://en.wikipedia.org/wiki/Open%E2%80%93closed_principle) entidades de software (classes, módulos, funções, etc.) devem ser abertas para extensão, mas fechadas para modificação.

# Banco de dados

A aplicação utiliza banco de dados relacional `(postgres)` e não relacional `(mongodb)`, a propósito de demonstração de conhecimento.

O banco de dados SQL pode ser gerenciado pela ferramenta de linha de comando `sequelize-cli`, as configurações estão presentes no diretório `config`.

## Migrations e Seeds

O utilitário `sequelize-cli` está configurado para realizar e reverter alterações no banco de dados utilizando os diretórios `migrations` e `seeders`.

## Rotas de aplicação

As rotas da aplicação podem ser importadas pelo arquivo `zrp-challenge-requests-http.json` utilizando o `insomnia`.

### Descrição das rotas:

### Authenticação
```sh
# [POST] Cadastro de novos usuários
http:localhost:3333/auth/signup   
``` 
```sh
# [POST] Login de usuários cadastrados
http:localhost:3333/auth/signin  
```
### Heróis
```sh
# [GET] Leitura de heróis
http:localhost:3333/heroes  
``` 
```sh
# [POST] Cadastro de heróis
http:localhost:3333/heroes  
``` 
```sh
# [PUT] Alteração de heróis
http:localhost:3333/heroes/:id 
``` 
```sh
# [DELETE] Remoção de heróis
http:localhost:3333/heroes/:id
``` 
### Ameaças
```sh
# [GET] Lista de ameaças a serem resolvidas
http:localhost:3333/threats  
``` 
### Ocorrencias
```sh
# [POST] Cadastro de nova ocorrência
http:localhost:3333/occurrence
```
### Batalhas
```sh
# [GET] Lista de batalhas (Ameaças resolvidas)
http:localhost:3333/battles  
```

# Scripts 

A seguir uma breve descrição dos scripts:

### Build
```sh
    npm run build # Executa o compilador typescript
```

### Start
```sh
    npm start # Inicia a aplicação node javascript
```

### Lint
```sh
    npm run lint # Padroniza o código fonte com regras eslint
```

### Migration
```sh
  npm run migration # Executa comandos DDL no banco de dados postgres
```

### Seeds
```sh
  npm run seeds # Insere uma lista de heróis pré-definida no banco de dados.
```

### Test
O framework utilizado para testes é o `vitest` e o seu arquivo de configuração é o `vite.config.mjs`.

O script de test também invoca os scripts `pretest` e `posttest`, responsáveis por configurar o banco de dados de teste da aplicação e reverter as alterações após os testes.


```sh
  npm test # Executa os testes da aplicação
```

### Dev
```sh
  npm run dev # Executa a aplicação em modo desenvolvimento
```
# Disclaimer

Para aplicação em modo produção, as variáveis de ambiente necessárias para executar o projeto não devem estar incluídas no repositório. Sendo este apenas uma demonstração, credenciais estão incluídas para facilitar a execução.

Para aplicativos de produção, utilizar .env.example com as variáveis necessárias com valor vazio.

# Contributions

Colabore com o projeto através de [Pull requests](https://github.com/ritecsuy-ariel/iheroes-backend/pulls).

# Issues

Encontrou algum erro? Reporte em [Issues](https://github.com/ritecsuy-ariel/iheroes-backend/issues)
