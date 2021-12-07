package oidc.model;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import org.springframework.format.annotation.DateTimeFormat;
public class ChangeAttributesRequest {

    @NotNull(message = "Can't be empty")
    @Size(min=1, message = "Must not be empty")
    private String firstName;

    @NotNull(message = "Can't be empty")
    @Size(min=1, message = "Must not be empty")
    private String lastName;

    @NotNull(message = "Can't be empty")
    @Size(min=1, message = "Must not be empty")
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private String birthdate;

    @NotNull(message = "Can't be empty")
    @Size(min=1, message = "Must not be empty")
    private String email;
}
