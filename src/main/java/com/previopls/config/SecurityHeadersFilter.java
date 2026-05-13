package com.previopls.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Headers de segurança aplicados a TODAS as respostas.
 *
 * Cobre OWASP secure headers baseline + ajustes para uma API JSON
 * (CSP restritivo para evitar uso indevido do Swagger UI no fluxo de prod).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class SecurityHeadersFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        // Força HTTPS quando exposto via proxy TLS (12 meses + subdomínios + preload)
        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
        // Bloqueia carregamento em <iframe> (clickjacking)
        response.setHeader("X-Frame-Options", "DENY");
        // Impede sniffing de content-type
        response.setHeader("X-Content-Type-Options", "nosniff");
        // Referrer mínimo
        response.setHeader("Referrer-Policy", "no-referrer");
        // Permissions Policy — desabilita features de browser não usadas
        response.setHeader("Permissions-Policy",
                "geolocation=(), microphone=(), camera=(), payment=(), usb=()");
        // CSP restritivo (a API só responde JSON; Swagger UI roda via CDN configurada)
        response.setHeader("Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");

        chain.doFilter(request, response);
    }
}
