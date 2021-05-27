package com.example.springsecurityfullcourse.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class Student {
    private final Integer studentId;
    private final String studentName;
}
