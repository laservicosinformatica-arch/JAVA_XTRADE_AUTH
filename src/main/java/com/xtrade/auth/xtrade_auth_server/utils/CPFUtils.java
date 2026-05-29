package com.xtrade.auth.xtrade_auth_server.utils;

public final class CPFUtils {

    private CPFUtils() {
    }

    public static String normalizeAndValidate(String cpf) {
        if (cpf == null) {
            throw new IllegalArgumentException("CPF is required");
        }

        String digits = cpf.replaceAll("\\D", "");

        if (!isValid(digits)) {
            throw new IllegalArgumentException("CPF is invalid");
        }

        return digits;
    }

    public static boolean isValid(String cpf) {
        if (cpf == null || !cpf.matches("\\d{11}")) {
            return false;
        }

        if (cpf.chars().distinct().count() == 1) {
            return false;
        }

        int firstDigit = calculateDigit(cpf.substring(0, 9), 10);
        int secondDigit = calculateDigit(cpf.substring(0, 9) + firstDigit, 11);

        return cpf.equals(cpf.substring(0, 9) + firstDigit + secondDigit);
    }

    private static int calculateDigit(String base, int weight) {
        int sum = 0;

        for (int i = 0; i < base.length(); i++) {
            int number = Character.getNumericValue(base.charAt(i));
            sum += number * (weight - i);
        }

        int result = 11 - (sum % 11);

        return result >= 10 ? 0 : result;
    }
}