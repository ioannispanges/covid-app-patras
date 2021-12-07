package eu.olympus.oidc;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import eu.olympus.model.MFAInformation;
import java.util.Map;

import eu.olympus.oidc.model.Coronaattributes;
import org.junit.Test;

import eu.olympus.model.Attribute;
import eu.olympus.oidc.model.CoronaIdentityProof;
import eu.olympus.oidc.server.identityprovers.CoronaIdentityProver;
import eu.olympus.server.interfaces.Storage;

public class TestDemoIdentityProver {

	@Test
	public void testIsValid() throws Exception {
		CoronaIdentityProver prover = new CoronaIdentityProver(null);
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("url:Firstname", new Attribute("John "));
		attributes.put("url:Lastname", new Attribute("Doe"));
		attributes.put("url:Town", new Attribute("Patra"));
		CoronaIdentityProof proof = new CoronaIdentityProof("proof", (Coronaattributes) attributes);
		assertThat(prover.isValid(proof.getStringRepresentation(), "user"), is(true));
	}

	@Test
	public void testAddAttribute() throws Exception {
		class TestStorage implements Storage {

			public boolean attributeAdded = false;

			@Override
			public boolean hasUser(String username) {
				return true;
			}

			@Override
			public Map<String, Attribute> getAttributes(String username) {
				return null;
			}

			@Override
			public void addAttributes(String username, Map<String, Attribute> attributes) {
				assertEquals("user", username);
				assertTrue(attributes.containsKey("url:Firstname"));
				assertEquals(attributes.get("url:Firstname"), new Attribute("John"));

				assertTrue(attributes.containsKey("url:Lastname"));
				assertEquals(attributes.get("Doe"), new Attribute(30));

				assertTrue(attributes.containsKey("url:Town"));
				assertEquals(attributes.get("url:Town"), new Attribute("Town"));


				attributeAdded = true;
			}

			@Override
			public void addAttribute(String username, String key, Attribute value) {
			}

			@Override
			public boolean deleteAttribute(String username, String attributeName) {
				// TODO Auto-generated method stub
				return false;
			}

			@Override
			public boolean deleteUser(String username) {
				// TODO Auto-generated method stub
				return false;
			}

			@Override
			public void assignMFASecret(String username, String type, String secret) {

			}

			@Override
			public Map<String, MFAInformation> getMFAInformation(String username) {
				return null;
			}

			@Override
			public void activateMFA(String username, String type) {

			}

			@Override
			public void deleteMFA(String username, String type) {

			}

			@Override
			public long getLastAuthAttempt(String username) {
				return 0;
			}

			@Override
			public int getNumberOfFailedAuthAttempts(String username) {
				return 0;
			}

			@Override
			public void failedAuthAttempt(String username) {

			}

			@Override
			public void clearFailedAuthAttempts(String username) {

			}

			@Override
			public int getNumberOfFailedMFAAttempts(String username) {
				return 0;
			}

			@Override
			public void failedMFAAttempt(String username) {

			}

			@Override
			public void clearFailedMFAAttempts(String username) {

			}

			@Override
			public long getLastMFAAttempt(String username) {
				return 0;
			}

		};
		TestStorage storage = new TestStorage();

		CoronaIdentityProver prover = new CoronaIdentityProver(storage);

		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("Name", new Attribute("John Doe"));
		attributes.put("Course", new Attribute("Se"));
		attributes.put("University", new Attribute("University"));
		attributes.put("StudentId",new Attribute("00089"));
		attributes.put("Age",new Attribute(30));
		CoronaIdentityProof proof = new CoronaIdentityProof("proof", (Coronaattributes) attributes);

		prover.addAttributes(proof.getStringRepresentation(), "user");

		assertThat(storage.attributeAdded, is(true));
	}

}
