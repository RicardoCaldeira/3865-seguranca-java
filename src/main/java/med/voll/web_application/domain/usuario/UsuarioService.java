package med.voll.web_application.domain.usuario;

import med.voll.web_application.domain.RegraDeNegocioException;
import med.voll.web_application.domain.usuario.email.EmailService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class UsuarioService implements UserDetailsService {

    private final UsuarioRepository usuarioRepository;
    private final EmailService emailService;
    private PasswordEncoder passwordEncoder;

    public UsuarioService(UsuarioRepository usuarioRepository, EmailService emailService, PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.emailService = emailService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return usuarioRepository.findByEmailIgnoreCase(username)
                .orElseThrow(() -> new UsernameNotFoundException("O usuário não foi encontrado!"));
    }

    public Long salvarUsuario(String nome, String email, Perfil perfil) {
        String primeiraSenha = UUID.randomUUID().toString().substring(0, 8);
        System.out.println("Senha gerada: " + primeiraSenha);
        String senhaCriptografada = passwordEncoder.encode(primeiraSenha);
        var usuario =usuarioRepository.save(new Usuario(nome, email, senhaCriptografada, perfil));
        return usuario.getId();
    }

    public void excluir(Long id) {
        usuarioRepository.deleteById(id);
    }

    public void alterarSenha(DadosAlteracaoSenha dados, Usuario logado) {
        if (!passwordEncoder.matches(dados.senhaAtual(), logado.getPassword())) {
            throw new RegraDeNegocioException("Senha digitada é diferente da senha atual!");
        }

        if (!dados.novaSenha().equals(dados.novaSenhaConfirmacao())) {
            throw new RegraDeNegocioException("A nova senha e a confirmação da nova senha são diferentes!");
        }

        String senhaCriptografada = passwordEncoder.encode(dados.novaSenha());
        logado.alterarSenha(senhaCriptografada);

        usuarioRepository.save(logado);
    }

    public void enviarToken(String email) {
        Usuario usuario = usuarioRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new RegraDeNegocioException("Usuario não encontrado!"));

        String token = UUID.randomUUID().toString();
        usuario.setToken(token);
        usuario.setExpiracaoToken(LocalDateTime.now().plusMinutes(15));
        usuarioRepository.save(usuario);

        emailService.enviarEmailSenha(usuario);
    }

    public void recuperarConta(String codigo, DadosRecuperacaoConta dados) {
        Usuario usuario = usuarioRepository.findByTokenIgnoreCase(codigo)
                .orElseThrow(() -> new RegraDeNegocioException("Token inválido!"));

        if (usuario.getExpiracaoToken() == null || LocalDateTime.now().isAfter(usuario.getExpiracaoToken())) {
            throw new RegraDeNegocioException("Link expirado!");
        }

        if (!dados.novaSenha().equals(dados.novaSenhaConfirmacao())) {
            throw new RegraDeNegocioException("A nova senha e a confirmação da nova senha são diferentes!");
        }

        String senhaCriptografada = passwordEncoder.encode(dados.novaSenha());
        usuario.alterarSenha(senhaCriptografada);
        usuario.setToken(null);
        usuario.setExpiracaoToken(null);
        usuarioRepository.save(usuario);
    }
}

