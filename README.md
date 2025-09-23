# API_Signalsafe
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// Rota de cadastro
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  const { data: userExists, error: checkError } = await supabase
    .from('users')
    .select('id')
    .eq('email', email)
    .maybeSingle();

  if (checkError) return res.status(500).json({ error: 'Erro ao verificar e-mail.' });
  if (userExists) return res.status(400).json({ error: 'E-mail já está cadastrado.' });

  const { data: signUpData, error: signUpError } = await supabase.auth.signUp({ email, password });
  if (signUpError) return res.status(400).json({ error: signUpError.message });

  const userId = signUpData.user.id;
  const hashedPassword = await bcrypt.hash(password, 10);

  const { error: insertError } = await supabase
    .from('users')
    .insert([{ id: userId, email, senha: hashedPassword, user_name: email, is_admin: false }]);

  if (insertError) return res.status(400).json({ error: insertError.message });

  return res.status(201).json({ message: 'Usuário cadastrado com sucesso.' });
});

// Rota de login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const { data: signInData, error: signInError } = await supabase.auth.signInWithPassword({ email, password });

  if (signInError) return res.status(400).json({ error: signInError.message });

  return res.status(200).json({ message: 'Login realizado com sucesso.', session: signInData.session, user: signInData.user });
});



//Rota de redefinir senha
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;


    if (!email) {
        return res.status(400).json({ error: 'O e-mail é obrigatório.' });
    }

    try {
        
        const { error } = await supabase.auth.resetPasswordForEmail(email, {
           
            redirectTo: 'https://signalsafe.com.br/reset-password',
        });

       
        if (error) {
            console.error('Erro ao enviar e-mail de redefinição:', error.message);
           
        }

        return res.status(200).json({
            message: 'Se o e-mail estiver registrado, você receberá um link de redefinição em sua caixa de entrada.'
        });

    } catch (err) {
       
        console.error('Erro interno do servidor:', err);
        return res.status(500).json({ error: 'Erro interno do servidor. Tente novamente mais tarde.' });
    }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
