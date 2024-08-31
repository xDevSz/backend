const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const secretKey = 'secreta'; // Guarde essa chave de forma segura

const app = express();

// Configuração do multer para upload de arquivos em memória
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Configuração do Express
app.use(cors());
app.use(express.json({ limit: '50mb' }));  // Limite aumentado para 50MB
app.use(express.urlencoded({ extended: true, limit: '50mb' }));  // Limite aumentado para 50MB

// Conexão com o banco de dados MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'alan',
  database: 'ecoplaint',
  port: 3306
});

db.connect(err => {
  if (err) {
    console.error('Erro ao conectar ao banco de dados:', err);
    return;
  }
  console.log('Conectado ao banco de dados MySQL');
});

// Middleware de autenticação para verificar JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.header('Authorization');
  if (!authHeader) {
    console.log('Token não fornecido.');
    return res.status(403).send('Acesso negado.');
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded;
    console.log('Usuário autenticado:', req.user);
    next();
  } catch (error) {
    console.log('Erro ao verificar o token:', error.message);
    res.status(401).send('Token inválido.');
  }
};

// Endpoint para cadastro com hash de senha
app.post('/api/cadastrar', async (req, res) => {
  const { nome, email, senha } = req.body;

  if (!nome || !email || !senha) {
    return res.status(400).send('Dados incompletos.');
  }

  try {
    const hashedPassword = await bcrypt.hash(senha, 10); // Hash da senha
    const query = 'INSERT INTO usuarios (usua_nome, usua_email, usua_senha) VALUES (?, ?, ?)';
    db.query(query, [nome, email, hashedPassword], (err, results) => {
      if (err) {
        console.error('Erro ao cadastrar usuário:', err);
        return res.status(500).send({
          error: 'Erro ao cadastrar usuário',
          details: err.message
        });
      }
      res.status(200).send('Usuário cadastrado com sucesso!');
    });
  } catch (error) {
    console.error('Erro ao cadastrar usuário:', error);
    res.status(500).send('Erro no servidor');
  }
});

// Endpoint para login com validação de senha e geração de JWT
app.post('/api/login', (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).send('E-mail e senha são obrigatórios.');
  }

  const query = 'SELECT * FROM usuarios WHERE usua_email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) {
      console.error('Erro ao buscar usuário:', err);
      return res.status(500).send('Erro no servidor');
    }

    if (results.length === 0) {
      return res.status(401).send('E-mail ou senha incorretos.');
    }

    const user = results[0];
    const isPasswordValid = await bcrypt.compare(senha, user.usua_senha);

    if (!isPasswordValid) {
      return res.status(401).send('E-mail ou senha incorretos.');
    }

    // Gera o token JWT usando 'usua_id_usuario' como chave
    const token = jwt.sign({ usua_id_usuario: user.usua_id_usuario }, secretKey, { expiresIn: '1h' });
    console.log('Token gerado:', token); // Log do token gerado
    res.status(200).json({ message: 'Login bem-sucedido!', token });
  });
});

// Endpoint para envio de denúncia com múltiplas imagens
app.post('/api/denuncia', authenticateJWT, upload.array('imagens', 4), async (req, res) => {
  const connection = db;  // Usa a conexão do MySQL existente
  connection.beginTransaction(err => {
    if (err) {
      console.error('Erro ao iniciar a transação:', err);
      return res.status(500).json({ message: 'Erro no servidor', error: err.message });
    }

    try {
      const { opcaoSelecionada, localizacao, manterAnonimo } = req.body;
      const imagensParaSalvar = req.files.map(file => file.buffer);

      if (!opcaoSelecionada || !localizacao || imagensParaSalvar.length === 0) {
        return res.status(400).json({ message: 'Dados faltando', data: req.body });
      }

      const userId = manterAnonimo === 'true' || manterAnonimo === true ? null : req.user.usua_id_usuario;

      console.log('Dados da denúncia:', { userId, opcaoSelecionada, localizacao, manterAnonimo });

      // Inserir a denúncia no banco de dados
      const denunciaQuery = `
        INSERT INTO denuncias (denu_id_usuario, denu_imagem, denu_categoria, denu_localizacao, denu_manter_anonimo, denu_dt_denuncia)
        VALUES (?, ?, ?, ?, ?, NOW())`;

      connection.query(denunciaQuery, [userId, imagensParaSalvar[0], opcaoSelecionada, localizacao, manterAnonimo ? 1 : 0], (err, results) => {
        if (err) {
          console.error('Erro ao registrar denúncia:', err);
          return connection.rollback(() => {
            res.status(500).json({ message: 'Erro ao registrar denúncia', error: err.message });
          });
        }

        const denunciaId = results.insertId;
        console.log('Denúncia registrada com ID:', denunciaId);

        // Inserir a notificação no banco de dados após a denúncia ser registrada
        const notiQuery = `
          INSERT INTO notificacoes (noti_id_usuario, noti_tipo_notificacao, noti_mensagem, noti_lida, noti_dt_envio)
          VALUES (?, ?, ?, ?, NOW())`;

        const mensagemNotificacao = `Denúncia enviada: ${opcaoSelecionada} em ${localizacao}`;
        console.log('Tentando inserir notificação com a mensagem:', mensagemNotificacao);

        connection.query(notiQuery, [userId, 'Push Notification', mensagemNotificacao, false], (err, result) => {
          if (err) {
            console.error('Erro ao registrar notificação:', err);
            return connection.rollback(() => {
              res.status(500).json({ message: 'Erro ao registrar notificação', error: err.message });
            });
          }

          console.log('Notificação registrada com sucesso:', result);

          // Confirma a transação
          connection.commit(err => {
            if (err) {
              console.error('Erro ao confirmar a transação:', err);
              return connection.rollback(() => {
                res.status(500).json({ message: 'Erro ao confirmar a transação', error: err.message });
              });
            }

            res.status(200).json({ message: 'Denúncia enviada e notificação registrada com sucesso' });
          });
        });
      });

    } catch (error) {
      console.error('Erro ao processar a denúncia:', error);
      return connection.rollback(() => {
        res.status(500).json({ message: 'Erro no servidor', error: error.message });
      });
    }
  });
});

// Endpoint para buscar todas as notificações
app.get('/api/notificacoes/todas', (req, res) => {
  const query = `
    SELECT noti_id_notificacao, noti_tipo_notificacao, noti_mensagem, noti_lida, 
           DATE_FORMAT(noti_dt_envio, '%d/%m/%Y %H:%i:%s') AS noti_dt_envio
    FROM notificacoes
    ORDER BY noti_dt_envio DESC`;

  db.query(query, (err, results) => {
    if (err) {
      console.error('Erro ao buscar notificações:', err);
      return res.status(500).json({ message: 'Erro ao buscar notificações', error: err.message });
    }

    res.status(200).json(results);
  });
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
