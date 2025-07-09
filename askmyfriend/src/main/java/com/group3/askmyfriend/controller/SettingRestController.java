// src/main/java/com/group3/askmyfriend/controller/SettingRestController.java

package com.group3.askmyfriend.controller;

import com.group3.askmyfriend.service.UserService;
import com.group3.askmyfriend.service.CustomUserDetailsService.CustomUser;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/setting")
@RequiredArgsConstructor
public class SettingRestController {

    private final UserService userService;

    /**
     * 1) 비밀번호 변경 (기존)
     *    요청 JSON: { "currentPassword": "...", "newPassword": "...", "confirmPassword": "..." }
     */
    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal CustomUser user
    ) {
        String current = body.get("currentPassword");
        String neu     = body.get("newPassword");
        String conf    = body.get("confirmPassword");

        try {
            Long userId = userService.findByLoginId(user.getUsername())
                                     .orElseThrow(() -> new IllegalArgumentException("사용자 정보가 없습니다."))
                                     .getUserId();

            userService.changePassword(userId, current, neu, conf);
            return ResponseEntity.ok(Map.of("message", "비밀번호가 변경되었습니다."));
        } catch (IllegalArgumentException e) {
            return ResponseEntity
                    .badRequest()
                    .body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * 2) 모바일: 비밀번호 재인증
     *    요청 JSON: { "password": "입력된 비밀번호" }
     *    성공 시 HTTP 200 { "result":"ok" }
     *    실패 시 HTTP 401 { "error":"비밀번호가 일치하지 않습니다." }
     */
    @PostMapping("/verify-password")
    public ResponseEntity<Map<String, String>> verifyPassword(
            @AuthenticationPrincipal CustomUser user,
            @RequestBody Map<String, String> body
    ) {
        String password = body.get("password");
        try {
            userService.validateLogin(user.getUsername(), password);
            return ResponseEntity.ok(Map.of("result", "ok"));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "비밀번호가 일치하지 않습니다."));
        }
    }

    /**
     * 3) 모바일: 전화번호 변경
     *    요청 JSON: { "newPhone": "010-1234-5678" }
     *    성공 시 HTTP 200 { "result":"ok" }
     */
    @PostMapping("/change-phone")
    public ResponseEntity<Map<String, String>> changePhone(
            @AuthenticationPrincipal CustomUser user,
            @RequestBody Map<String, String> body
    ) {
        String newPhone = body.get("newPhone");
        userService.findByLoginId(user.getUsername())
                   .ifPresent(u -> userService.updatePhone(u.getUserId(), newPhone));
        return ResponseEntity.ok(Map.of("result", "ok"));
    }
}
