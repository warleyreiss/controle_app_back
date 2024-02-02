const express = require("express")
var cors = require('cors')
const { Pool } = require('pg')
const multer = require("multer")
const path = require("path")
const session = require('express-session')
const flash = require('connect-flash')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { Console } = require("console")
const { geteuid } = require("process")
const { getDefaultHighWaterMark } = require("stream")
const { get } = require("http")
const fs = require('fs');
const imageDataURI = require('image-data-uri')
require('dotenv').config()
const PORT = process.env.PORT || 8080
const pool = new Pool({
    connectionString: process.env.POSTGRES_URL || "postgres://itlciaeb:1-WPNlUxLrrety67AONnYGWqLBesWR1s@kesavan.db.elephantsql.com/itlciaeb"
})
const app = express()
app.use(cors())
// configurar leitura de objetos json no projeto
app.use(express.json())

const dataHora = new Date();
dataHora.setHours(dataHora.getHours() - 3);

app.get('/', (req, res) => {
    res.status(200).json({ msg: "bem- vindo! status:" + dataHora + "| -v 1.0" })
})

//teste rota protegida por token
app.get('/teste/login', checkToken, async (req, res) => {
    res.status(200).json({ test: 'acesso liberado' })
})

const secret = "WARLEYGONCALVESDOSREIS"

// criando o middleware para confimar o tokem de autenticação do usuario
function checkToken(req, res, next) {

    // crio a constante recebendo o parametro authorization do header da solicitação
    const autHeader = req.headers['authorization']
    //extraio o token separando o array pelo "" e pegando a segunda parte
    const tokenRecebido = autHeader && autHeader.split(" ")[1]

    //verificando se há tokem recebido
    if (!tokenRecebido) {
        res.status(401).json({ msg: "necessario fazer login" })
    }

    try {
        //testando se o tokem confere

        const decoded = jwt.verify(tokenRecebido, secret);
        next()

    } catch (error) {
        //res.status(422).json({ msg: "tokem invalido", error })
    }
}

app.post('/authentication/signin', async (req, res) => {
    const { email, password } = req.body

    try {
        if (email && password) {
            //requisição no banco
            const getUser = await pool.query('SELECT * FROM users where email=($1)', [email])
            //verificar se a senha digitada confere com a do banco
            const confirmPassaWord = await bcrypt.compare(password, getUser.rows[0].password)
            //se nao conferir envio msg de erro
            if (confirmPassaWord) {
                console.log('estou aqui ')
                const getProject = await pool.query('SELECT * FROM projects where id=($1)', [getUser.rows[0].project_id])
                const token = jwt.sign(
                    {
                        userid: getUser.rows[0].id,
                        project_id: getProject.rows[0].id,
                    },
                    secret,
                )
                //teste particular para enviar mais de q parametro
                res.status(200).json({
                    token: token,
                    userId: getUser.rows[0].id,
                    userName: getUser.rows[0].name,
                    userType: getUser.rows[0].type,
                    userEmail: getUser.rows[0].email,
                    userImage: getUser.rows[0].image,
                    projectId: getProject.rows[0].id,
                    projectName: getProject.rows[0].name,
                    projectPlan: getProject.rows[0].plan,
                    msg: "Seja bem vindo novamente!",
                })
            } else {
                res.status(422).json({ msg_alert: "Senha e usuários não conferem" })
            }
        } else {
            res.status(422).json({ msg_alert: "Preencha todos os campos" })
        }
    } catch {

        res.status(400).json({ msg_alert: "usuario não encontrado" })
    }
})
app.post('/authentication/reset', async (req, res) => {
    const { email } = req.body
    try {
        if (email) {
            const password = Math.floor(Math.random() * 99999).toString()
            const passwordBcrypt = await bcrypt.hash(password, 12)
            console.log('pass é ' + password)
            const updateUser = await pool.query('UPDATE users SET reset_password=($1) where email=($2) RETURNING *', [passwordBcrypt, email])
            //enviar por email, se receber msg positiva prosigo
            res.status(200).json({ msg_alert: "Um código de segurança foi enviado em seu email" })
        } else {
            res.status(422).json({ msg_alert: "Informe seu email" })
        }
    } catch (err) {

        res.status(400).json({ msg_alert: "Algo errado aconteceu" })
    }
})
app.post('/authentication/reseted', async (req, res) => {
    const { email, secret, password } = req.body
    try {
        if (email) {
            const getUser = await pool.query("SELECT id, reset_password from users where email=($1)", [email])

            const confirmPassaWord = await bcrypt.compare(secret, getUser.rows[0].reset_password)
            if (confirmPassaWord) {
                console.log('oi3')
                const passwordBcrypt = await bcrypt.hash(password, 12)
                const updateUser = await pool.query('UPDATE users SET password=($1) where id=($2) RETURNING *', [passwordBcrypt, getUser.rows[0].id])
                console.log(updateUser.rows[0])
                res.status(200).json({ msg_alert: "Senha alterada, gentileza fazer login" })
            } else {
                res.status(400).json({ msg_alert: "]código de segurnaça incorreto" })
            }
        } else {
            res.status(422).json({ msg_alert: "Informe seu email" })
        }
    } catch (err) {
        res.status(400).json({ msg_alert: "Algo errado aconteceu" })
    }
})

//Projeto ________________________________________________________________________________________________
app.post('/project/create', async (req, res) => {
    const { nameUser, email, nameProject, password } = req.body;

    try {
        const getUser = await pool.query("SELECT * from users where email=($1)", [email])
        if (getUser.rowCount < 1) {
            const salt = await bcrypt.genSalt(12)
            const passwordBcrypt = await bcrypt.hash(password, salt)
            const newProject = await pool.query('INSERT INTO projects (name) VALUES ($1) RETURNING *', [nameProject])
            const newUser = await pool.query('INSERT INTO users (name, email, type,project_id,password) VALUES ($1,$2,$3,$4,$5) RETURNING *', [nameUser, email, 'MANAGER', newProject.rows[0].id, passwordBcrypt])
            const token = jwt.sign(
                {
                    userid: newUser.rows[0].id,
                    project_id: newProject.rows[0].id,
                },
                secret,
            )
            //ENCAMINHANDO OS DADOS NECESSÁRIOS AO FRONT
            return res.status(200).json({
                token: token,
                userId: newUser.rows[0].id,
                userName: newUser.rows[0].name,
                userType: newUser.rows[0].type,
                userEmail: newUser.rows[0].email,
                userImage: newUser.rows[0].image,
                projectId: newProject.rows[0].id,
                projectName: newProject.rows[0].name,
                projectPlan: newProject.rows[0].plan,
                msg: "Seu novo projeto foi criado com sucesso!",
            })
        } else {
            return res.status(400).json({ msg: 'Email já cadastrado' })
        }
    } catch (err) {
        return res.status(400).json({ msg: "Esse email já está em uso: " })
    }
})
app.get('/project/read/:id', checkToken, async (req, res) => {
    const id = req.params.id
    try {
        if (id) {
            const getProjet = await pool.query("SELECT * from projects where id=($1)", [id])
            res.status(200).json({ registros: getProjet.rows[0] })
        }
    } catch (err) {
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.patch('/project/update', checkToken, async (req, res) => {
    const { project_id, email, name, phone, cpf_cnpj, logo } = req.body;
    try {
        const updateProject = await pool.query('UPDATE projects SET name=($1),cpf_cnpj=($2),phone=($3),logo=($4),email=($5) where id=($6) RETURNING *', [name, cpf_cnpj, phone, logo, email, project_id])
        res.status(200).json({
            projectName: updateProject.rows[0].name,
            projectCpf_cnpj: updateProject.rows[0].cpf_cnpj,
            projectEmail: updateProject.rows[0].email,
            projectPhone: updateProject.rows[0].phone,
            projectLogo: updateProject.rows[0].logo,
        })
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.post('/project/merchant/create', checkToken, async (req, res) => {
    const { nameMerchant, emailMerchant, phoneMerchant, project_id } = req.body;
    try {
        nameMerchant.map(async (linha, key) => {
            let newMerchant = await pool.query('INSERT INTO merchants (name,email,phone,project_id) VALUES ($1,$2,$3,$4) RETURNING *', [linha, emailMerchant[key], phoneMerchant[key], project_id])

        })
        const getMerchants = await pool.query("SELECT * from merchants where project_id=($1) AND status!='0' ORDER BY id ASC", [project_id])
        res.status(200).send(getMerchants.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/project/merchants/:id', checkToken, async (req, res) => {
    const id = req.params.id
    try {
        const getMerchants = await pool.query("SELECT * from merchants where project_id=($1) AND status!='0'", [id])

        res.status(200).send(getMerchants.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/project/merchant/read/:id', checkToken, async (req, res) => {
    const { id } = req.body;
    try {
        const getMerchant = await pool.query("SELECT * from merchant where id=($1)", [id])
        res.status(200).send(getMerchant.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.patch('/project/merchant/delete/:id', checkToken, async (req, res) => {
    const id = req.params.id;
    console.log('aqui remove')
    try {
        const updateMerchants = await pool.query('UPDATE merchants SET status=($1) where id=($2) RETURNING *', [0, id])

        res.status(200).json({ msg: "Fornecedor removido!" })
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})

//equipment________________________________________________________________________________________________
app.get('/equipment/epis', checkToken, async (req, res) => {
    try {
        const getEpis = await pool.query("SELECT * from epis")
        res.status(200).send(getEpis.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/equipments', checkToken, async (req, res) => {
    const autHeader = req.headers['authorization']
    const tokenRecebido = autHeader && autHeader.split(" ")[1]
    const decoded = jwt.verify(tokenRecebido, secret);
    try {

        const getEquipments = await pool.query("SELECT equipments.price,equipments.classification_size_id,equipments.current_balance,equipments.id,equipments.ideal_balance,equipments.price,equipments.validity,  CASE WHEN equipments.current_balance >= equipments.ideal_balance THEN 'ALTO' WHEN equipments.current_balance < equipments.ideal_balance THEN 'BAIXO' END status_balance,classification_sizes.size,epis.type from equipments JOIN epis ON equipments.epi_id=epis.id JOIN classification_sizes ON equipments.classification_size_id=classification_sizes.id where equipments.project_id=($1) AND equipments.status=($2) ORDER BY equipments.id DESC", [decoded.project_id, 1])

        res.status(200).send(getEquipments.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/equipment/read/:id', checkToken, async (req, res) => {
    const { id } = req.params;

    try {

        const getEquipment = await pool.query("SELECT equipments.epi_id, equipments.classification_size_id,equipments.current_balance,equipments.id,equipments.ideal_balance,equipments.price,equipments.validity FROM equipments where equipments.id=($1)", [id])

        if (getEquipment.rowCount < 1) {
            return res.status(400).json({ msg: "Houve um erro na solicitação: " })
        } else {
            res.status(200).send(getEquipment.rows[0])
        }

    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/equipment/classification_sizes/:epi_id', checkToken, async (req, res) => {
    const { epi_id } = req.params;
    try {
        const getEpis = await pool.query("SELECT * from epis where id=($1)", [epi_id])
        const getClassification = await pool.query("SELECT * from classification_sizes where classification_size=($1)", [getEpis.rows[0].classification_size])

        res.status(200).send(getClassification.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})

app.post('/equipment/create', checkToken, async (req, res) => {
    const { epi_id, classification_size_id, validity, ideal_balance, current_balance, price } = req.body;
    try {
        const autHeader = req.headers['authorization']
        const tokenRecebido = autHeader && autHeader.split(" ")[1]
        const decoded = jwt.verify(tokenRecebido, secret);
        console.log(decoded)

        const getEquipment = await pool.query("SELECT classification_size_id,epi_id, project_id from equipments where  classification_size_id=($1) AND epi_id=($2) AND project_id=($3) AND status=($4)", [classification_size_id, epi_id, decoded.project_id, 1])
        if (getEquipment.rowCount > 0) {
            return res.status(400).json({ msg: "Parece que você já tem esse equipameto cadastro em seu projeto!" })
        }
        const newEquipment = await pool.query('INSERT INTO equipments (epi_id, classification_size_id, validity, ideal_balance, current_balance, price,project_id ) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [epi_id, classification_size_id, validity, ideal_balance, current_balance, price, decoded.project_id])
        console.log(newEquipment.rows[0].id)
        if (newEquipment.rowCount > 0) {
            const newRegistro = await pool.query("SELECT equipments.classification_size_id,equipments.current_balance,equipments.id,equipments.ideal_balance,equipments.price,equipments.validity, classification_sizes.size,CASE WHEN equipments.current_balance >= equipments.ideal_balance THEN 'ALTO' WHEN equipments.current_balance < equipments.ideal_balance THEN 'BAIXO' END status_balance,epis.type from equipments JOIN epis ON equipments.epi_id=epis.id JOIN classification_sizes ON equipments.classification_size_id=classification_sizes.id where equipments.project_id=($1) AND equipments.id=($2)", [decoded.project_id, newEquipment.rows[0].id])
            res.status(200).send(newRegistro.rows[0])
        }
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.post('/equipment/buy/create', checkToken, async (req, res) => {
    const { merchant_id, list_equipment_id, qty, current_price } = req.body;
    console.log(req.body)
    try {
        const autHeader = req.headers['authorization']
        const tokenRecebido = autHeader && autHeader.split(" ")[1]
        const decoded = jwt.verify(tokenRecebido, secret);

        list_equipment_id.map(async (equipment, key) => {
            if (qty[key]) {
                console.log(qty[key])
                const updateEquipment = await pool.query('UPDATE equipments SET price=($1), current_balance= current_balance+($2) where id=($3) and project_id=($4) RETURNING *', [current_price[key], qty[key], equipment, decoded.project_id])
                const newBuyEquipment = await pool.query('INSERT INTO buy_histories ( merchant_id, equipment_id,current_price, qty,project_id) VALUES ($1,$2,$3,$4,$5) RETURNING *', [merchant_id, equipment, current_price[key], qty[key], decoded.project_id])

                console.log('feito')
            } else {
                console.log('fim')
            }
        })
        return res.status(200).json({ msg: "Registrado" })
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/equipment/history/:equipment_id', checkToken, async (req, res) => {
    const { equipment_id } = req.params;
    try {
        const getHistoryBuy = await pool.query("SELECT  buy_histories.qty, to_char(buy_histories.created_at, 'DD/MM/YYYY') as date, merchants.name as merchantname from buy_histories JOIN merchants ON buy_histories.merchant_id=merchants.id where equipment_id=($1) ORDER BY buy_histories.id DESC  LIMIT 10", [equipment_id])
        const getHistoryProvided = await pool.query("SELECT  provided_histories.qty, to_char(provided_histories.provided_at, 'DD/MM/YYYY') as date, employees.name as employeename from provided_histories JOIN employees ON provided_histories.employee_id=employees.id where equipment_id=($1) ORDER BY provided_histories.id DESC  LIMIT 10", [equipment_id])
        res.status(200).json({ listBuy: getHistoryBuy.rows, listProvided: getHistoryProvided.rows })
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/equipment/cart', checkToken, async (req, res) => {
    const autHeader = req.headers['authorization']
    const tokenRecebido = autHeader && autHeader.split(" ")[1]
    const decoded = jwt.verify(tokenRecebido, secret);
    console.log(decoded.project_id)
    try {

        const getCart = await pool.query("SELECT equipments.id,(equipments.ideal_balance - equipments.current_balance) as qty, epis.type,classification_sizes.size, equipments.epi_id FROM equipments JOIN epis ON equipments.epi_id=epis.id JOIN classification_sizes ON equipments.classification_size_id=classification_sizes.id where equipments.ideal_balance > equipments.current_balance and equipments.project_id=($1) and equipments.status=($2)", [decoded.project_id, '1'])

        res.status(200).send(getCart.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})

app.patch('/equipment/update', checkToken, async (req, res) => {
    const { id, epi_id, classification_size_id, validity, ideal_balance, current_balance, price } = req.body;
    try {
        const autHeader = req.headers['authorization']
        const tokenRecebido = autHeader && autHeader.split(" ")[1]
        const decoded = jwt.verify(tokenRecebido, secret);
        const updateEquipment = await pool.query('UPDATE equipments SET  classification_size_id=($1),  validity=($2), ideal_balance=($3), current_balance=($4), price=($5) where id=($6) and project_id=($7) RETURNING *', [classification_size_id, validity, ideal_balance, current_balance, price, id, decoded.project_id])
        //data de validação nao pode ser menor que hoje
        //se prazo de validade for menor que o atual, alguns fornecimentos por passar a estar vencidos
        const Registro = await pool.query("SELECT equipments.classification_size_id,equipments.current_balance,equipments.id,equipments.ideal_balance,equipments.price,equipments.validity, classification_sizes.size,CASE WHEN equipments.current_balance >= equipments.ideal_balance THEN 'ALTO' WHEN equipments.current_balance < equipments.ideal_balance THEN 'BAIXO' END status_balance, epis.type from equipments JOIN epis ON equipments.epi_id=epis.id JOIN classification_sizes ON equipments.classification_size_id=classification_sizes.id where equipments.project_id=($1) AND equipments.id=($2)", [decoded.project_id, updateEquipment.rows[0].id])
        res.status(200).send(Registro.rows[0])
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})

app.patch('/equipment/delete/:id', checkToken, async (req, res) => {
    const { id } = req.params;
    try {
        const autHeader = req.headers['authorization']
        const tokenRecebido = autHeader && autHeader.split(" ")[1]
        const decoded = jwt.verify(tokenRecebido, secret);

        const getType = await pool.query("SELECT epi_id from equipments where id=($1)", [id])
        const getEquipment = await pool.query("SELECT epi_id from equipments where epi_id=($1) AND project_id=($2) AND status=($3)", [getType.rows[0].epi_id, decoded.project_id, 1])

        if (getEquipment.rowCount <= 1) {
            //verifico aqui as funcões
            return res.status(400).json({ msg: "Você não pode excluir esse equipamento, pois está vinculado a um cargo/função" })
        } else {
            const deleteEquipment = await pool.query('UPDATE equipments SET status=($1) where id=($2) and project_id=($3) RETURNING *', [0, id, decoded.project_id])
            res.status(200).json({ msg: "Excluído com sucesso(s)" })
        }

    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/equipments/inputType', checkToken, async (req, res) => {
    const autHeader = req.headers['authorization']
    const tokenRecebido = autHeader && autHeader.split(" ")[1]
    const decoded = jwt.verify(tokenRecebido, secret);
    try {
        const getEquipments = await pool.query("SELECT DISTINCT equipments.epi_id ,epis.type  from equipments JOIN epis ON equipments.epi_id=epis.id where equipments.project_id=($1) AND equipments.status=($2) ORDER BY epis.type ASC", [decoded.project_id, 1])

        res.status(200).send(getEquipments.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/equipments/size_provide/:id', checkToken, async (req, res) => {
    const { id } = req.params
    const autHeader = req.headers['authorization']
    const tokenRecebido = autHeader && autHeader.split(" ")[1]
    const decoded = jwt.verify(tokenRecebido, secret);
    console.log(id)
    try {
        const getsizes = await pool.query("SELECT equipments.id,equipments.classification_size_id,classification_sizes.size FROM equipments JOIN classification_sizes ON equipments.classification_size_id=classification_sizes.id where equipments.epi_id=($1) AND equipments.status=($2) AND equipments.project_id=($3)", [id, 1, decoded.project_id])
        console.log(getsizes.rows)
        res.status(200).send(getsizes.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})

//offices________________________________________________________________________________________________
app.post('/office/create', checkToken, async (req, res) => {
    const { name, selected, label } = req.body;
    try {
        const autHeader = req.headers['authorization']
        const tokenRecebido = autHeader && autHeader.split(" ")[1]
        const decoded = jwt.verify(tokenRecebido, secret);

        const getOffice = await pool.query("SELECT name from offices where  name=($1) AND project_id=($2) AND status=($3)", [name, decoded.project_id, 1])
        if (getOffice.rowCount > 0) {
            return res.status(400).json({ msg: "Parece que você já tem esse cargo/função cadastro em seu projeto!" })
        }
        const newOffice = await pool.query('INSERT INTO offices (name,epi_id, project_id ) VALUES ($1,$2,$3) RETURNING *', [name, selected, decoded.project_id])
        if (newOffice.rowCount > 0) {
            const newOffice2 = await pool.query("SELECT * FROM offices where offices.id=($1) AND project_id=($2)", [newOffice.rows[0].id, decoded.project_id])
            return res.status(200).send(newOffice2.rows[0])
            //res.status(200).send(newEquipment.rows[0])
        }
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/offices', checkToken, async (req, res) => {
    const autHeader = req.headers['authorization']
    const tokenRecebido = autHeader && autHeader.split(" ")[1]
    const decoded = jwt.verify(tokenRecebido, secret);
    try {
        const getOffices = await pool.query("SELECT * FROM offices where project_id=($1) AND status=($2) ORDER BY name ASC", [decoded.project_id, 1])
        res.status(200).send(getOffices.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})

app.get('/office/read/:id', checkToken, async (req, res) => {
    const { id } = req.params;

    try {
        const getOffice = await pool.query("SELECT * FROM offices where offices.id=($1)", [id])
        if (getOffice.rowCount < 1) {
            return res.status(400).json({ msg: "Houve um erro na solicitação: " })
        } else {
            res.status(200).send(getOffice.rows[0])
        }

    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})

app.patch('/office/update', checkToken, async (req, res) => {
    const { id, selected, name } = req.body;

    try {
        const autHeader = req.headers['authorization']
        const tokenRecebido = autHeader && autHeader.split(" ")[1]
        const decoded = jwt.verify(tokenRecebido, secret);
        const getOffice = await pool.query("SELECT * FROM offices where offices.id=($1)", [id])
        const now = getOffice.rows[0].epi_id

        // função para comparar os array e identificar quais sairam
        var epi_id_out = now.filter(function (element, index, array) {
            if (selected.indexOf(element) == -1)
                return element;
        });
        // função para comparar os array e identificar quais entraram
        var epi_id_in = selected.filter(function (element, index, array) {
            if (now.indexOf(element) == -1)
                return element;
        });
        console.log('acresentou:' + epi_id_in)

        if (epi_id_in.length > 0 || epi_id_out.length > 0) {
            const getEmployees = await pool.query("SELECT id FROM employees where office_id=($1) AND project_id=($2) AND status=($3)", [id, decoded.project_id, 1])
            console.log('serão afetados:'+getEmployees.rowCount)
          epi_id_out.map(async (epi, key) => {
                getEmployees.rows.map(async (employee, key) => {
                    let removeControl = await pool.query('UPDATE controls SET status=($1) where epi_id=($2) and employee_id=($3) and office_id=($4) and project_id=($5)RETURNING *', [0, epi, employee.id, id, decoded.project_id])
                    console.log(removeControl.rows)
                })

            })
            epi_id_in.map(async (epi, key) => {
                getEmployees.rows.map(async (employee, key) => {
                    let newControl = await pool.query('INSERT INTO controls (employee_id,office_id,epi_id,project_id,motive) VALUES ($1,$2,$3,$4,$5) RETURNING *', [employee.id, id, epi, decoded.project_id, 6])
                    console.log(newControl.rows)
                })

            })
            
        }

        const updateOffice = await pool.query('UPDATE offices SET epi_id=($1),name=($2) where id=($3) and project_id=($4) RETURNING *', [selected, name, id, decoded.project_id])
        const getOffice2 = await pool.query("SELECT * FROM offices where offices.id=($1) AND project_id=($2)", [id, decoded.project_id])
        //saber quais epis sairam e entraram
        res.status(200).send(getOffice2.rows[0])
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})

app.patch('/office/delete/:id', checkToken, async (req, res) => {
    const { id } = req.params;
    try {
        const autHeader = req.headers['authorization']
        const tokenRecebido = autHeader && autHeader.split(" ")[1]
        const decoded = jwt.verify(tokenRecebido, secret);

        const getEmployees = await pool.query("SELECT id from employees where office_id=($1) and status=($2)", [id, 1])
        if (getEmployees.rowCount > 0) {
            return res.status(400).json({ msg: "Você não pode excluir esse cargo/função, pois tem colaboradores exercendo ela" })
        }
        const deleteEmloyees = await pool.query('UPDATE offices SET status=($1) where id=($2) and project_id=($3) RETURNING *', [0, id, decoded.project_id])
        res.status(200).json({ msg: "Excluído com sucesso(s)" })
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/offices/inputType', checkToken, async (req, res) => {
    const autHeader = req.headers['authorization']
    const tokenRecebido = autHeader && autHeader.split(" ")[1]
    const decoded = jwt.verify(tokenRecebido, secret);
    try {
        const getOffices = await pool.query("SELECT DISTINCT offices.id, offices.name from offices where offices.project_id=($1) AND offices.status=($2) ORDER BY offices.name ASC", [decoded.project_id, 1])

        res.status(200).send(getOffices.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
//employees________________________________________________________________________________________________
app.post('/employee/create', checkToken, async (req, res) => {
    const { name, registration, office_id, size_shirt, size_pant, size_shoe, size_respirator } = req.body;
    try {
        const autHeader = req.headers['authorization']
        const tokenRecebido = autHeader && autHeader.split(" ")[1]
        const decoded = jwt.verify(tokenRecebido, secret);

        const getEmployee = await pool.query("SELECT registration from employees where  registration=($1) AND project_id=($2) AND status=($3)", [registration, decoded.project_id, 1])
        if (getEmployee.rowCount > 0) {
            return res.status(400).json({ msg: "Parece que você já cadastrou esse colaborador em seu projeto!" })
        }
        const newEmployee = await pool.query('INSERT INTO employees (name, registration, office_id, size_shirt, size_pant, size_shoe, size_respirator, project_id ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *', [name, registration, office_id, size_shirt, size_pant, size_shoe, size_respirator, decoded.project_id])

        const getEquipments = await pool.query("SELECT epi_id from offices where id=($1) AND project_id=($2) AND status=($3)", [newEmployee.rows[0].office_id, decoded.project_id, 1])

        getEquipments.rows[0].epi_id.map(async (epi, key) => {
            let newControl = await pool.query('INSERT INTO controls (employee_id,office_id,epi_id,project_id,motive) VALUES ($1,$2,$3,$4,$5) RETURNING *', [newEmployee.rows[0].id, newEmployee.rows[0].office_id, epi, decoded.project_id, 1])
        })

        if (newEmployee.rowCount > 0) {
            const newEmployee2 = await pool.query("SELECT employees.id, employees.registration,employees.name, employees.office_id,employees.size_shirt,employees.size_pant, employees.size_shoe,employees.size_respirator,offices.name as nameOffice FROM employees JOIN offices ON employees.office_id =offices.id where employees.id=($1) AND employees.project_id=($2)", [newEmployee.rows[0].id, decoded.project_id])
            return res.status(200).send(newEmployee2.rows[0])
        }
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/employees', checkToken, async (req, res) => {
    const autHeader = req.headers['authorization']
    const tokenRecebido = autHeader && autHeader.split(" ")[1]
    const decoded = jwt.verify(tokenRecebido, secret);
    try {
        const getEmployees = await pool.query("SELECT employees.id,employees.registration, employees.name, employees.office_id,employees.size_shirt,employees.size_pant, employees.size_shoe,employees.size_respirator,offices.name as nameOffice FROM employees JOIN offices ON employees.office_id =offices.id where employees.project_id=($1) AND employees.status !=($2)", [decoded.project_id, 0])
        res.status(200).send(getEmployees.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})

app.get('/employee/read/:id', checkToken, async (req, res) => {
    const { id } = req.params;

    try {
        const getOffice = await pool.query("SELECT * FROM employees where employees.id=($1)", [id])
        if (getOffice.rowCount < 1) {
            return res.status(400).json({ msg: "Houve um erro na solicitação: " })
        } else {
            res.status(200).send(getOffice.rows[0])
        }

    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})

app.patch('/employee/update', checkToken, async (req, res) => {
    const { id, name, registration, office_id, size_shirt, size_pant, size_shoe, size_respirator } = req.body;

    try {
        const autHeader = req.headers['authorization']
        const tokenRecebido = autHeader && autHeader.split(" ")[1]
        const decoded = jwt.verify(tokenRecebido, secret);

        const getEmployee = await pool.query("SELECT  employees.id, employees.office_id FROM employees where employees.id=($1)", [id])

        if (getEmployee.rows[0].office_id != office_id) {
            console.log('diferente')
            const getEquipmentsBefore = await pool.query("SELECT offices.epi_id FROM offices where offices.id=($1)", [getEmployee.rows[0].office_id])
            const getEquipmentsAfter = await pool.query("SELECT offices.epi_id FROM offices where offices.id=($1)", [office_id])
            console.log('antes:' + getEquipmentsBefore.rows[0].epi_id)
            console.log('agora:' + getEquipmentsAfter.rows[0].epi_id)
            // função para comparar os array e identificar quais sairam
            var epi_id_out = getEquipmentsBefore.rows[0].epi_id.filter(function (element, index, array) {
                if (getEquipmentsAfter.rows[0].epi_id.indexOf(element) == -1)
                    return element;
            });
            console.log('removeu:' + epi_id_out)
            epi_id_out.map(async (epi, key) => {
                let removeControl = await pool.query('UPDATE controls SET status=($1) where epi_id=($2) and employee_id=($3) and project_id=($4)RETURNING *', [0, epi, getEmployee.rows[0].id, decoded.project_id])
                console.log(removeControl.rows)
            })



            // função para comparar os array e identificar quais entraram
            var epi_id_in = getEquipmentsAfter.rows[0].epi_id.filter(function (element, index, array) {
                if (getEquipmentsBefore.rows[0].epi_id.indexOf(element) == -1)
                    return element;
            });
            console.log('acresentou:' + epi_id_in)
            epi_id_in.map(async (epi, key) => {
                let newControl = await pool.query('INSERT INTO controls (employee_id,office_id,epi_id,project_id,motive) VALUES ($1,$2,$3,$4,$5) RETURNING *', [getEmployee.rows[0].id, office_id, epi, decoded.project_id, 8])
                console.log(newControl.rows)
            })
        }

        const updateEmployee = await pool.query('UPDATE employees SET  name=($1), registration=($2), office_id=($3), size_shirt=($4), size_pant=($5), size_shoe=($6), size_respirator=($7)  where id=($8) and project_id=($9) RETURNING *', [name, registration, office_id, size_shirt, size_pant, size_shoe, size_respirator, id, decoded.project_id])
        const getEmployee2 = await pool.query("SELECT employees.id, employees.registration,employees.name, employees.office_id,employees.size_shirt,employees.size_pant, employees.size_shoe,employees.size_respirator,offices.name as nameOffice FROM employees JOIN offices ON employees.office_id =offices.id where employees.id=($1) AND employees.project_id=($2)", [updateEmployee.rows[0].id, decoded.project_id])
        //saber quais epis sairam e entraram

        res.status(200).send(getEmployee2.rows[0])
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})

app.patch('/employee/delete/:id', checkToken, async (req, res) => {
    const { id } = req.params;
    try {
        const autHeader = req.headers['authorization']
        const tokenRecebido = autHeader && autHeader.split(" ")[1]
        const decoded = jwt.verify(tokenRecebido, secret);

        const deleteEmloyees = await pool.query('UPDATE employees SET status=($1) where id=($2) and project_id=($3) RETURNING *', [0, id, decoded.project_id])
        const deleteControls = await pool.query('UPDATE controls SET status=($1) where employee_id=($2) and project_id=($3) RETURNING *', [0, id, decoded.project_id])
        res.status(200).json({ msg: "Excluído com sucesso(s)" })
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/employees/inputType', checkToken, async (req, res) => {
    const autHeader = req.headers['authorization']
    const tokenRecebido = autHeader && autHeader.split(" ")[1]
    const decoded = jwt.verify(tokenRecebido, secret);
    try {
        const getEmployees = await pool.query("SELECT id, name,registration from employees where project_id=($1) AND status=($2) ORDER BY name ASC", [decoded.project_id, 1])
        console.log(getEmployees.rows)
        res.status(200).send(getEmployees.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/employee/provide/:id', checkToken, async (req, res) => {
    const { id } = req.params
    const autHeader = req.headers['authorization']
    const tokenRecebido = autHeader && autHeader.split(" ")[1]
    const decoded = jwt.verify(tokenRecebido, secret);
    try {
        const getEmployee = await pool.query("SELECT office_id FROM employees where project_id=($1) AND status=($2) AND id=($3)", [decoded.project_id, 1, id])
        const getEpi = await pool.query("SELECT epi_id from offices where project_id=($1) AND status=($2) and id=($3)", [decoded.project_id, 1, getEmployee.rows[0].office_id])
        //aprender a pesquisar arrays
        const numberArray = getEpi.rows[0].epi_id.map(Number);
        const getProvide = await pool.query("SELECT id, type, classification_size from epis where id= any($1)", [numberArray])
        res.status(200).send(getProvide.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})

//Controls________________________________________________________________________________________________
app.get('/controls', checkToken, async (req, res) => {
    const autHeader = req.headers['authorization']
    const tokenRecebido = autHeader && autHeader.split(" ")[1]
    const decoded = jwt.verify(tokenRecebido, secret);
    try {
        const getControls = await pool.query("SELECT controls.id,controls.approval_certificate,controls.equipment_id,controls.qty,CASE WHEN controls.provided_at  >= now() THEN 'EM DIA' WHEN controls.provided_at < now()  THEN 'VENCIDO' ELSE 'PENDENTE' END statuscontrol,to_char(controls.provided_at, 'DD/MM/YYYY') as provided_at ,CASE WHEN controls.motive = '1' THEN 'ADMISSAO' WHEN controls.motive = '2' THEN 'TROCA PERIODICA' WHEN controls.motive = '3' THEN 'DESGASTE IRREGULAR' WHEN controls.motive = '4' THEN 'DESGASTE JUSTIFICADO' WHEN controls.motive = '5' THEN 'PERCA/EXTRAVIO' WHEN controls.motive = '6' THEN 'NOVO EPI VINCULADO A FUNCAO' WHEN controls.motive = '8' THEN 'MUDANÇA DE FUNÇÃO' END motive,epis.type,employees.name as nameemployee,offices.name as nameoffice,equipments.classification_size_id,classification_sizes.size FROM controls JOIN epis ON controls.epi_id= epis.id JOIN employees ON controls.employee_id=employees.id JOIN offices ON controls.office_id=offices.id LEFT JOIN equipments ON controls.equipment_id= equipments.id LEFT JOIN classification_sizes ON equipments.classification_size_id=classification_sizes.id  where controls.project_id=($1) AND controls.status=($2) ORDER BY controls.provided_at desc", [decoded.project_id, 1])
        res.status(200).send(getControls.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.patch('/control/update', checkToken, async (req, res) => {
    const { id, employee_id, epi_id, classification_size_id, approval_certificate, qty, motive, provided_at } = req.body;
    // no campo  classification_size_id na verdade eu recebo o id do equipamento, esta foi uma forma de driblar a necessiadade

    const dataHora = new Date();
    dataHora.setHours(dataHora.getHours() - 3);
    let getInfo=''
    let history=''
    console.log('começando...')
    try {
        const autHeader = req.headers['authorization']
        const tokenRecebido = autHeader && autHeader.split(" ")[1]
        const decoded = jwt.verify(tokenRecebido, secret);

        if(req.body.id){
            console.log('consultando por ID')
             getInfo = await pool.query("SELECT to_char(controls.provided_at, 'YYYY-MM-DD') as provided_at,id,office_id  from controls where id=($1) and project_id=($2) and status=($3)", [id, decoded.project_id, 1])
        }else{
            console.log('buscando registro anterior sem id...')
            getInfo = await pool.query("SELECT to_char(controls.provided_at, 'YYYY-MM-DD') as provided_at,id,equipment_id,epi_id,employee_id,office_id  from controls where employee_id=($1) and epi_id=($2) and project_id=($3) and status=($4)", [employee_id, epi_id, decoded.project_id, 1])
        }
        console.log(getInfo.rows[0])
        console.log('alterando equipamentos')
        const getEquipment = await pool.query('UPDATE equipments SET current_balance= current_balance+($1) where id=($2) and project_id=($3) RETURNING *', [qty, classification_size_id ?? getInfo.rows[0].equipment_id, decoded.project_id])
        console.log(getEquipment.rows[0])
        console.log('verificando dadas...')
        console.log(getInfo.rows[0].provided_at)
        if (getInfo.rows[0].provided_at < provided_at || !getInfo.rows[0].provided_at) {
            const updateControl = await pool.query('UPDATE controls SET equipment_id=($1),approval_certificate=($2), qty=($3), motive=($4), provided_at=($5), current_price=($6) where employee_id=($7) and epi_id=($8) and project_id=($9) and status=($10) RETURNING *', [getEquipment.rows[0].id, approval_certificate, qty, motive, provided_at, getEquipment.rows[0].price, employee_id ?? getInfo.rows[0].employee_id, epi_id ?? getInfo.rows[0].epi_id, decoded.project_id, 1])
            history=false
            console.log('lançado no controle')
            console.log(updateControl.rows[0])
        }else{
            console.log('somente historico')
             history=true
            //else: somente hisotrico
        }
        const newProvidedEquipment = await pool.query('INSERT INTO provided_histories (control_id,employee_id,office_id, epi_id, equipment_id, approval_certificate, qty, motive, provided_at,current_price,project_id,just_history) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *', [getInfo.rows[0].id,employee_id ?? getInfo.rows[0].employee_id, getInfo.rows[0].office_id, getEquipment.rows[0].epi_id, getEquipment.rows[0].id, approval_certificate, qty, motive, provided_at, getEquipment.rows[0].price, decoded.project_id,history])
       res.status(200).send(newProvidedEquipment.rows[0])

    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/control/read/:id', checkToken, async (req, res) => {
    const { id } = req.params;
    try {
        const getControl = await pool.query("SELECT * FROM controls where id=($1)", [id])
        if (getControl.rowCount < 1) {
            return res.status(400).json({ msg: "Houve um erro na solicitação: " })
        } else {
            res.status(200).send(getControl.rows[0])
        }

    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
//classification_sizes________________________________________________________________________________________________
app.get('/classification_sizes/shirts', checkToken, async (req, res) => {

    try {
        const getShits = await pool.query("SELECT * FROM classification_sizes where classification_size=($1) ORDER BY id ASC", [1])

        res.status(200).send(getShits.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/classification_sizes/pants', checkToken, async (req, res) => {

    try {
        const getShits = await pool.query("SELECT * FROM classification_sizes where classification_size=($1) ORDER BY id ASC", [3])

        res.status(200).send(getShits.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/classification_sizes/shoes', checkToken, async (req, res) => {

    try {
        const getShits = await pool.query("SELECT * FROM classification_sizes where classification_size=($1) ORDER BY id ASC", [4])

        res.status(200).send(getShits.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/classification_sizes/respirators', checkToken, async (req, res) => {
    try {
        const getRespirators = await pool.query("SELECT * FROM classification_sizes where classification_size=($1) ORDER BY id ASC", [2])
        res.status(200).send(getRespirators.rows)
    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
// historys _____________________________________________________________________________________________________________
app.patch('/history/read', checkToken, async (req, res) => {
    const { firstDate, endDate } = req.body;
    const autHeader = req.headers['authorization']
    const tokenRecebido = autHeader && autHeader.split(" ")[1]
    const decoded = jwt.verify(tokenRecebido, secret);

    const employee_id = []
    req.body.employee_id.map((id) => { employee_id.push(id.value) })
    const epi_id = []
    req.body.epi_id.map((id) => { epi_id.push(id.value) })
    console.log(employee_id, epi_id)

    try {
        const getHistorys = await pool.query("SELECT provided_histories.id,provided_histories.approval_certificate,provided_histories.equipment_id,provided_histories.qty,to_char(provided_histories.provided_at, 'DD/MM/YYYY') as provided_at ,CASE WHEN provided_histories.motive = '1' THEN 'ADMISSAO' WHEN provided_histories.motive = '2' THEN 'TROCA PERIODICA' WHEN provided_histories.motive = '3' THEN 'DESGASTE IRREGULAR' WHEN provided_histories.motive = '4' THEN 'DESGASTE JUSTIFICADO' WHEN provided_histories.motive = '5' THEN 'PERCA/EXTRAVIO' WHEN provided_histories.motive = '6' THEN 'NOVO EPI VINCULADO A FUNCAO' WHEN provided_histories.motive = '8' THEN 'MUDANÇA DE FUNÇÃO' END motive,epis.type,employees.name as nameemployee,offices.name as nameoffice,equipments.classification_size_id,classification_sizes.size FROM provided_histories JOIN epis ON provided_histories.epi_id= epis.id JOIN employees ON provided_histories.employee_id=employees.id JOIN offices ON provided_histories.office_id=offices.id LEFT JOIN equipments ON provided_histories.equipment_id= equipments.id LEFT JOIN classification_sizes ON equipments.classification_size_id=classification_sizes.id  where provided_histories.project_id=($1) AND provided_histories.epi_id=any($2)  AND provided_histories.employee_id =any($3) AND provided_histories.provided_at BETWEEN ($4) AND ($5) ORDER BY provided_histories.provided_at desc", [decoded.project_id, epi_id, employee_id, firstDate, endDate])

        res.status(200).send(getHistorys.rows)

    } catch (err) {
        console.log(err)
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.get('/teste', async (req, res) => {
    try {
        const getTest = await pool.quey("SELECT * from projects")
        return res.status(200).send(getTest.rows)
    } catch (err) {
        return res.status(400).json({ msg: "Houve um erro na solicitação: " + err })
    }
})
app.listen(PORT, () => console.log("servidor iniciado! porta: " + PORT))