package oidc.configuration;

import com.nimbusds.jose.jwk.RSAKey;
import eu.olympus.client.*;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.client.storage.InMemoryCredentialStorage;
import eu.olympus.model.Operation;
import eu.olympus.model.PabcPublicParameters;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;

import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import javax.net.ssl.HostnameVerifier;

import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.verifier.PSPABCVerifier;
import oidc.model.DiscoveryLoader;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;

@Configuration
public class OidcConfiguration {
    private static final byte[] seed = "random value random value random value random value random".getBytes();

    @Value("${pesto.servers.http}")
    private String servers;

    /**
     * Initiates the user client. Requires that all pesto IDPs are running.
     *
     * @return user client
     */

    @Bean
    public UserClient createUserClient() throws Exception {
        String[] serverArray = servers.split(",");
        List<PestoIdPRESTConnection> idps = new ArrayList<PestoIdPRESTConnection>();
        UserClient client = null;
		Properties systemProps = System.getProperties();
		systemProps.put("javax.net.ssl.trustStore", "src/test/resources/truststore.jks");
		systemProps.put("javax.net.ssl.trustStorePassword", "OLYMPUS");
		// Ensure that there is a certificate in the trust store for the webserver connecting
		HostnameVerifier verifier = new DefaultHostnameVerifier();
		javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(verifier);

        for (int i = 0; i < serverArray.length; i++) {
            System.out.println("Server " + i + 1 + ": " + serverArray[i]);
            PestoIdPRESTConnection idp = new PestoIdPRESTConnection(serverArray[i], "", i, 100000);
            idps.add(idp);
        }
        ClientCryptoModule crypto = new SoftwareClientCryptoModule(new SecureRandom(), ((RSAPublicKey) idps.get(0).getCertificate().getPublicKey()).getModulus());
System.out.println("crypto created");
        client = new PestoClient(idps, crypto);
        return client;
    }
//        List<PabcIdPRESTConnection> idps = new ArrayList<>();
//        int serverCount = 3;
//        String administratorCookie = "eimLN2/sr73deAVV8D/3FXFUNbSRdu3d/FJtWLCXGhu9+i6fiHcS54MyIOG6MczVR7r941CI+H1dbgDIVi+xHQ==";
//        int[] ports = new int[serverCount];
//        int basePort = 9080;
//        for (int i = 0; i < serverCount; i++)
//
//            ports[i] = basePort + i;
//        for (int i = 0; i < serverCount; i++) {
//
//            PabcIdPRESTConnection rest = new PabcIdPRESTConnection("https://localhost:" + (ports[i]),
//                    administratorCookie, i, 100000);
//            idps.add(rest);
//        }
//
//        Map<Integer, MSverfKey> publicKeys = new HashMap<>();
//        for (Integer j = 0; j < serverCount; j++) {
//            publicKeys.put(j, idps.get(j).getPabcPublicKeyShare());
//        }
//        PabcPublicParameters publicParam = idps.get(0).getPabcPublicParam();
//        CredentialManagement credentialManagement = new PSCredentialManagement(true, new InMemoryCredentialStorage());
//        ((PSCredentialManagement) credentialManagement).setup(publicParam, publicKeys, seed);
//
//        ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), ((RSAPublicKey) idps.get(0).getCertificate().getPublicKey()).getModulus());
//
//        UserClient client = new PabcClient(idps, credentialManagement, cryptoModule);
//        PSPABCVerifier verifier = new PSPABCVerifier();
//        verifier.setup(idps, seed);
//        return null;
//    }

    /**
     * The policy used when authenticating a login request.
     *
     * @return policy
     */

    @Bean
    public Policy policy() {
        List<Predicate> predicates = new ArrayList<>();
        predicates.add(new Predicate("name", Operation.REVEAL, null));
        predicates.add(new Predicate("birthdate", Operation.REVEAL, null));
        predicates.add(new Predicate("course", Operation.REVEAL, null));
        predicates.add(new Predicate("university", Operation.REVEAL, null));
        predicates.add(new Predicate("studentid", Operation.REVEAL, null));


        Policy policy = new Policy();
        policy.setPredicates(predicates);
        return policy;
    }

    @Bean
    public RSAKey certs() throws Exception {
        String[] serverArray = servers.split(",");
        PabcIdPRESTConnection idp = new PabcIdPRESTConnection(serverArray[0], "", 0, 100000);
        return new RSAKey.Builder((RSAPublicKey) idp.getCertificate().getPublicKey()).build();
    }

    @Bean
    public DiscoveryLoader discoveryLoader() {
        return new DiscoveryLoader("src/main/resources/openid-configuration-discovery");
    }

    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/login").setViewName("login");
    }

}
