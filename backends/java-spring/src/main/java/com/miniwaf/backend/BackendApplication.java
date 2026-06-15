package com.miniwaf.backend;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * Test backend for mini-waf — listens on port 33335 (set in application.properties).
 *
 * Endpoints:
 *   GET  /                catch_all tier
 *   GET  /health          health check
 *   ANY  /api/echo        echoes method/path/headers/query/body
 *   GET  /api/hello       high tier
 *   GET  /api/users       high tier
 *   POST /login           critical tier
 *   GET  /user/{id}       high tier
 *   GET  /static/test.txt medium tier
 */
@SpringBootApplication
@RestController
public class BackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(BackendApplication.class, args);
    }

    @GetMapping("/")
    public Map<String, String> root() {
        return Map.of("backend", "spring", "message", "hello from Spring backend");
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("healthy", true);
    }

    @RequestMapping("/api/echo")
    public ResponseEntity<Map<String, Object>> echo(HttpServletRequest request) throws IOException {
        Map<String, String> headers = new LinkedHashMap<>();
        Collections.list(request.getHeaderNames())
                .forEach(name -> headers.put(name, request.getHeader(name)));

        Map<String, String> query = new LinkedHashMap<>();
        String qs = request.getQueryString();
        if (qs != null) {
            for (String pair : qs.split("&")) {
                String[] kv = pair.split("=", 2);
                query.put(kv[0], kv.length > 1 ? kv[1] : "");
            }
        }

        String body = request.getReader().lines().collect(Collectors.joining("\n"));

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("method", request.getMethod());
        result.put("path", request.getRequestURI());
        result.put("headers", headers);
        result.put("query", query);
        result.put("body", body);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/api/hello")
    public Map<String, String> hello() {
        return Map.of("message", "hello from Spring");
    }

    @GetMapping("/api/users")
    public java.util.List<Map<String, Object>> getUsers() {
        return java.util.List.of(
            Map.of("id", 1, "name", "Alice", "backend", "spring"),
            Map.of("id", 2, "name", "Bob", "backend", "spring")
        );
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody(required = false) Map<String, Object> data) {
        if (data == null) data = Map.of();
        String username = (String) data.getOrDefault("username", "unknown");
        return Map.of("token", "test-token-spring", "user", username);
    }

    @GetMapping("/user/{id}")
    public Map<String, String> getUser(@PathVariable String id) {
        return Map.of("id", id, "name", "User " + id, "backend", "spring");
    }

    @GetMapping("/static/test.txt")
    public ResponseEntity<String> staticFile() {
        return ResponseEntity.ok()
                .header("Content-Type", "text/plain")
                .body("Hello from static file (Spring backend)\n");
    }
}
