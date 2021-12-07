package oidc.controller;

import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeIdentityProof;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.ExistingUserException;
import eu.olympus.model.exceptions.TokenGenerationException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.IdentityProof;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import oidc.model.ChangePasswordRequest;
import oidc.model.CreateUserRequest;
import oidc.model.LoginRequest;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;
import eu.olympus.model.exceptions.OperationFailedException;

@Controller
public class OidcController {
    //private static final Logger logger = LoggerFactory.getLogger(OidcController.class);

    @Autowired
    UserClient userClient;

    @Autowired
    Policy policy;

    // Login form
    @RequestMapping("/login")
    public String login(Model model, @RequestParam String redirect_uri, @RequestParam String state, @RequestParam String nonce, HttpServletRequest request) {
        request.getSession().setAttribute("redirectUrl", redirect_uri);
        request.getSession().setAttribute("state", state);
        request.getSession().setAttribute("nonce", nonce);
        LoginRequest loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        policy.setPolicyId(nonce);
        return "/login";
    }


    @RequestMapping("/loginPage")
    public String loginPage(Model model ) {
        LoginRequest loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        model.addAttribute("hasCreated", false);
        return "/login";
    }
////
    @PostMapping("/authenticate")
    public RedirectView authenticate(LoginRequest loginRequest, Model model, HttpServletRequest request) throws AuthenticationFailedException, TokenGenerationException {
        try {
            String token = userClient.authenticate(loginRequest.getUsername(), loginRequest.getPassword(), policy, null, "NONE");
            model.addAttribute("username", loginRequest.getUsername());
            model.addAttribute("token", token);
            String redirectUrl = (String) request.getSession().getAttribute("redirectUrl");
            String state = (String) request.getSession().getAttribute("state");
            return new RedirectView(redirectUrl + "#state=" + state + "&id_token=" + token + "&token_type=bearer");
        } catch (Exception e) {
            if (ExceptionUtils.indexOfThrowable(e, AuthenticationFailedException.class) != -1) {
                return new RedirectView("/loginFailed", true);
            } else {
                throw e;
            }
        } finally {
            userClient.clearSession();
        }
    }
//
//    @PostMapping("/manageAccountAuthenticate")
//    public RedirectView manageAccountAuthenticate(LoginRequest loginRequest, Model model, HttpServletRequest request)
//            throws AuthenticationFailedException, OperationFailedException {
//        try {
//            String token = userClient.authenticate(loginRequest.getUsername(), loginRequest.getPassword(), policy, null, "NONE");
//           Map<String, Attribute> attributes = userClient.getAllAttributes(loginRequest.getUsername(), loginRequest.getPassword(),"NONE");
//            request.getSession().setAttribute("name", attributes.get("name"));
//            request.getSession().setAttribute("email", attributes.get("email"));
//            request.getSession().setAttribute("birthdate", attributes.get("birthdate"));
//            model.addAttribute("username", loginRequest.getUsername());
//            model.addAttribute("token", token);
//            return new RedirectView("/manageAccount");
//        } catch (Exception e) {
//            if (ExceptionUtils.indexOfThrowable(e, AuthenticationFailedException.class) != -1) {
//                return new RedirectView("/loginFailed", true);
//            } else {
//                throw e;
//            }
//        } finally {
//            userClient.clearSession();
//        }
//    }
    // Login form
    @RequestMapping("/loginFailed")
    public String login(Model model) {
        LoginRequest loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        model.addAttribute("loginError", true);
        return "/login";
    }

    // Create User form
    @RequestMapping("/createUser")
    public String createNewUser(Model model) {
        model.addAttribute("userExists", false);
        CreateUserRequest createUserRequest = new CreateUserRequest();
        model.addAttribute("createUserRequest", createUserRequest);
        return "/createUser";
    }

    @PostMapping("/createUser")
    public String postUser(@Valid CreateUserRequest createUserRequest, BindingResult bindingResult, Model model) {
        IdentityProof identityProof = constructIdentityProof(createUserRequest);
        if (bindingResult.hasErrors()) {
            return "/createUser";
        }
        try {
            userClient.createUserAndAddAttributes(createUserRequest.getUsername(), createUserRequest.getPassword(), identityProof);
        } catch (Exception exception) {
            if (ExceptionUtils.indexOfThrowable(exception, ExistingUserException.class) != -1) {
                model.addAttribute("userExists", true);
            } else if(ExceptionUtils.indexOfThrowable(exception, AuthenticationFailedException.class) != -1){
                model.addAttribute("userExists", true);
            } else {
                model.addAttribute("unknownError", true);
            }
            //logger.warn("Create user failed: " + exception);

            return "/createUser";
        }
        LoginRequest loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        model.addAttribute("hasCreated", true);
        userClient.clearSession();
        return "/login";
    }

    private AttributeIdentityProof constructIdentityProof(CreateUserRequest createUserRequest) {
        Map<String, Attribute> attributes = new HashMap<>();
        attributes.put("name", new Attribute(createUserRequest.getFirstName() + " " + createUserRequest.getLastName()));
        attributes.put("birthdate",new Attribute(createUserRequest.getBirthdate()));
        attributes.put("course", new Attribute(createUserRequest.getCourse()));
        attributes.put("studentid", new Attribute(createUserRequest.getStudentid()));
        attributes.put("university", new Attribute(createUserRequest.getUniversity()));


        return new AttributeIdentityProof(attributes);
    }

    @RequestMapping("/changePassword")
    public String changePassword(Model model) {
        ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
        model.addAttribute("changePasswordRequest", changePasswordRequest);
        return "/changePassword";
    }


    @PostMapping("/changePassword")
    public String postChangePassword(@Valid ChangePasswordRequest changePasswordRequest, BindingResult bindingResult, Model model) {
        if (bindingResult.hasErrors()) {
            return "/changePassword";
        }
        try {
            userClient.changePassword(changePasswordRequest.getUsername(), changePasswordRequest.getOldPassword(), changePasswordRequest.getNewPassword(),null, "NONE");
        } catch (Exception exception) {
            if (ExceptionUtils.indexOfThrowable(exception, UserCreationFailedException.class) != -1) {
                model.addAttribute("passwordChangeError", true);
            } else if (ExceptionUtils.indexOfThrowable(exception, AuthenticationFailedException.class) != -1) {
                model.addAttribute("usernameWrongError", true);
            } else {
                model.addAttribute("unknownError", true);
            }
            return "/changePassword";
        }
        LoginRequest loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        model.addAttribute("hasChangedPassword", true);
        userClient.clearSession();
        return "/login";
    }


    @RequestMapping("/deleteAccount")
    public String deleteAccount(Model model) {
        LoginRequest loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        return "/deleteAccount";
    }


    @PostMapping("/deleteAccount")
    public String postDeleteAccount(LoginRequest loginRequest, Model model) {
        try {
            userClient.deleteAccount(loginRequest.getUsername(), loginRequest.getPassword(), null, "NONE");
        } catch (Exception exception) {
            if (ExceptionUtils.indexOfThrowable(exception, AuthenticationFailedException.class) != -1) {
                model.addAttribute("userDeletionError", true);
            } else {
                model.addAttribute("unknownError", true);
            }
            return "/deleteAccount";
        }
        loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        model.addAttribute("hasDeletedAccount", true);
        return "/login";
    }

}
