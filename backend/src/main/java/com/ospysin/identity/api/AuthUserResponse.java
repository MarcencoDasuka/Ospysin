package com.ospysin.identity.api;

import com.ospysin.identity.UserRole;

import java.util.UUID;

public record AuthUserResponse(
        UUID id,
        String username,
        UserRole role
) {}
