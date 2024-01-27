package org.university.payment_for_utilities.services.implementations.tools;

import lombok.NonNull;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;

import java.math.BigDecimal;

import static org.university.payment_for_utilities.services.implementations.tools.ExceptionTools.throwRuntimeException;

public class FinanceTools {
    private static final int FRACTIONAL_ACCURACY = 2;
    private static final String COMPLEMENT_SYMBOL = "0";
    private static final String FIXED_COST_TEMPLATE = "^\\d+\\.?\\d{0,2}$";

    public static final BigDecimal EMPTY_BIG_DECIMAL = BigDecimal.ZERO;

    private FinanceTools() {}

    public static @NonNull BigDecimal convertStringToBigDecimal(@NonNull String money) {
        int indexPoint = money.lastIndexOf(".");

        if(indexPoint < 0) {
            money += ".";
            indexPoint = money.length() - 1;
        }

        int fractionalValue = money.length() - indexPoint - 1;

        if(fractionalValue < FRACTIONAL_ACCURACY) {
            money += COMPLEMENT_SYMBOL.repeat(FRACTIONAL_ACCURACY - fractionalValue);
        }

        return new BigDecimal(money);
    }

    public static void validateFinance(@NonNull String argumentName, @NonNull String fixedCost) throws InvalidInputDataException {
        if(isFixedCost(fixedCost)){
            return;
        }

        var message = String.format("The value you provided: \"%s\" in the \"%s\" aggregate failed to validate. It should contain only a fractional number separated by a period.", argumentName, fixedCost);
        throwRuntimeException(message, InvalidInputDataException::new);
    }

    private static boolean isFixedCost(@NonNull String fixedCost) {
        return fixedCost.isBlank() || fixedCost
                .matches(FIXED_COST_TEMPLATE);
    }
}
