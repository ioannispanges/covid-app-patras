package eu.olympus.completeFlow;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import eu.olympus.client.PSCredentialManagement;
import eu.olympus.client.PabcClient;
import eu.olympus.client.PabcIdPRESTConnection;
import eu.olympus.client.SoftwareClientCryptoModule;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.client.storage.InMemoryCredentialStorage;
import eu.olympus.model.PabcPublicParameters;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.PabcIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdPRESTWrapper;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PabcIdP;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.rest.PabcIdPServlet;
import eu.olympus.server.rest.PestoIdP2IdPRESTConnection;
import eu.olympus.server.rest.RESTIdPServer;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.unit.server.TestIdentityProver;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.verifier.PSPABCVerifier;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestPabcCompleteFlow extends CommonCompleteTests{
    private static Logger logger = LoggerFactory.getLogger(TestPabcCompleteFlow.class);

    private static Map<Integer, PestoDatabase> databases = new HashMap<Integer, PestoDatabase>();

    private List<PabcIdPImpl> setupPabcIdPs(int amount) {
        if (amount != getServerCount()) {
            throw new IllegalArgumentException("Configuration only supports " + getServerCount() + " servers");
        }
        List<PabcIdPImpl> idps = new ArrayList<PabcIdPImpl>();
        databases = new HashMap<>();
        for(int i = 0; i< amount; i++) {
            databases.put(i,  new InMemoryPestoDatabase());
            PabcIdPImpl idp = null;
            List<IdentityProver> provers = new LinkedList<IdentityProver>();
            provers.add(new TestIdentityProver(databases.get(i)));
            SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(i));
            try {
                Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
                mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(crypto));
                mfaAuthenticators.put("dummy", new DummyAuthenticator());
                idp = new PabcIdPImpl(databases.get(i), provers, mfaAuthenticators, crypto, 10000000);
            } catch(Exception e) {
                fail("Failed to start IdP");
            }
            idps.add(idp);
        }
        return idps;
    }


    @Test
    public void testPabcPestoDirect() throws Exception {
        logger.info("Starting testPabcPestoDirect");
        int serverCount = 3;
        List<PabcIdPImpl> idps = setupPabcIdPs(serverCount);
        for(int i = 0; i< serverCount; i++) {
            try {
                PabcIdPImpl idp = idps.get(i);
                List<PabcIdP> others = new ArrayList<PabcIdP>();
                others.addAll(idps);
                others.remove(idp);

                boolean res = idp.setup("setup", configuration[i], others);
                assertTrue(res);
            } catch(Exception e) {
                fail("Failed to start IdP");
            }
        }

        Map<Integer, MSverfKey> publicKeys = new HashMap<>();
        for (Integer j = 0; j< serverCount; j++){
            publicKeys.put(j, idps.get(j).getPabcPublicKeyShare());
        }

        CredentialManagement credentialManagement=new PSCredentialManagement(true, new InMemoryCredentialStorage());
        ((PSCredentialManagement)credentialManagement).setup(idps,seed);

        ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), ((RSAPublicKey)idps.get(0).getCertificate().getPublicKey()).getModulus());

        UserClient client = new PabcClient(idps, credentialManagement, cryptoModule);

        PSPABCVerifier verifier = new PSPABCVerifier();
        verifier.setup(idps,seed);

        testSimpleFlowPabc(client,verifier);
        testRefreshFlowPabc(client, verifier, idps);
        CredentialManagement credentialManagementWithoutStorage=new PSCredentialManagement(false, null);
        ((PSCredentialManagement)credentialManagementWithoutStorage).setup(idps,seed);
        testMFAFlowPabc(new PabcClient(idps, credentialManagementWithoutStorage, cryptoModule), verifier);
    }

    @Test
    public void testPabcPestoREST() throws Exception{
        logger.info("Starting testPabcPestoREST");
        int serverCount = 3;
        List<PabcIdPImpl> idps = setupPabcIdPs(serverCount);
        List<RESTIdPServer> restServers = new ArrayList<>();
        List<String> servlets=new LinkedList<>();
        servlets.add(PabcIdPServlet.class.getCanonicalName());

        for(int i = 0; i< serverCount; i++) {
            try {
                RESTIdPServer restServer = new RESTIdPServer();
                restServer.setIdP(idps.get(i));
                restServer.start(configuration[i].getPort(), servlets, 0, null, null, null);
                restServers.add(restServer);
            } catch (Exception e) {
                fail("Failed to start IdP");
            }
        }
        List<PabcIdP> restIdps = new ArrayList<>();
        for(int i = 0; i< serverCount; i++) {
            try {
                PabcIdPRESTConnection restConnection = new PabcIdPRESTConnection("http://127.0.0.1:"+(configuration[i].getPort()),
                    getAdminCookie(), i, 100000);
                List<IdPRESTWrapper> others = new ArrayList<>();
                for(int j = 0; j< serverCount; j++) {
                    if (j != i) {
                        others.add(new PestoIdP2IdPRESTConnection("http://127.0.0.1:" + (configuration[j].getPort()), j,
                            configuration[i].getMyAuthorizationCookie()));
                    }
                }
                for(String cookie: configuration[i].getAuthorizationCookies().keySet()) {
                    idps.get(i).addSession(cookie, configuration[i].getAuthorizationCookies().get(cookie));
                }
                boolean res = idps.get(i).setup("setup", configuration[i], others);
                assertTrue(res);
                restIdps.add(restConnection);
            } catch(Exception e) {
                fail("Failed to connect servers");
            }
        }

        Map<Integer, MSverfKey> publicKeys = new HashMap<>();
        for (Integer j = 0; j< serverCount; j++){
            publicKeys.put(j, restIdps.get(j).getPabcPublicKeyShare());
        }
        PabcPublicParameters publicParam= restIdps.get(0).getPabcPublicParam();

        CredentialManagement credentialManagement=new PSCredentialManagement(true, new InMemoryCredentialStorage());
        ((PSCredentialManagement)credentialManagement).setup(publicParam,publicKeys,seed);

        ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), configuration[0].getKeyMaterial().getModulus());

        UserClient client = new PabcClient(restIdps, credentialManagement, cryptoModule);
        PSPABCVerifier verifier = new PSPABCVerifier();
        verifier.setup(idps,seed);
        testSimpleFlowPabc(client, verifier);
        testRefreshFlowPabc(client, verifier, restIdps);
        CredentialManagement credentialManagementWithoutStorage=new PSCredentialManagement(false, null);
        ((PSCredentialManagement)credentialManagementWithoutStorage).setup(publicParam,publicKeys,seed);
        testMFAFlowPabc(new PabcClient(restIdps, credentialManagementWithoutStorage, cryptoModule), verifier);
        for(RESTIdPServer server:restServers){
            server.stop();
        }
    }

    @Ignore
    @Test
    public void testPabcPestoAlreadySetup() throws Exception{
        logger.info("Starting testPabcPestoAlreadySetup");
        List<PabcIdPRESTConnection> idps = new ArrayList<PabcIdPRESTConnection>();
        int serverCount = 3;
        String administratorCookie="eimLN2/sr73deAVV8D/3FXFUNbSRdu3d/FJtWLCXGhu9+i6fiHcS54MyIOG6MczVR7r941CI+H1dbgDIVi+xHQ==";
        int[] ports=new int[serverCount];
        int basePort=9080;
        for(int i=0;i<serverCount;i++)
            ports[i]=basePort+i;
        for(int i = 0; i< serverCount; i++) {
            PabcIdPRESTConnection rest = new PabcIdPRESTConnection("http://127.0.0.1:"+(ports[i]),
                administratorCookie, i, 100000);
            idps.add(rest);
        }

        Map<Integer, MSverfKey> publicKeys = new HashMap<>();
        for (Integer j = 0; j< serverCount; j++){
            publicKeys.put(j, idps.get(j).getPabcPublicKeyShare());
        }
        PabcPublicParameters publicParam= idps.get(0).getPabcPublicParam();
        CredentialManagement credentialManagement=new PSCredentialManagement(true, new InMemoryCredentialStorage());
        ((PSCredentialManagement)credentialManagement).setup(publicParam,publicKeys,seed);

        ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), ((RSAPublicKey)idps.get(0).getCertificate().getPublicKey()).getModulus());

        UserClient client = new PabcClient(idps, credentialManagement, cryptoModule);
        PSPABCVerifier verifier = new PSPABCVerifier();
        verifier.setup(idps,seed);
        testSimpleFlowPabc(client, verifier);
    }


}
