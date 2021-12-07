package eu.olympus.oidc.server.identityprovers;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.model.Attribute;
import eu.olympus.oidc.model.CoronaIdentityProof;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.util.Util;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Token verifier. Adds the unique value of the token as a user attribute
 * Currently no verification is done, may involve a signature in the
 * future.
 *
 */
public class CoronaIdentityProver implements IdentityProver {
	private Storage storage;

	public CoronaIdentityProver(Storage storage) throws Exception {
		this.storage = storage;
	}

	@Override
	public boolean isValid(String idProof, String username) {

		return true;
	}

	@Override
	public void addAttributes(String proof, String username) {
		CoronaIdentityProof obj = getProof(proof);
		if(obj != null) {
			Map<String, Attribute> proverAttributes = new HashMap<>();
			proverAttributes.put("url:DateOfBirth", new Attribute(Util.fromRFC3339UTC(obj.getData().getDateOfBirth())));
			proverAttributes.put("url:Firstname", new Attribute(obj.getData().getFirstname()));
			proverAttributes.put("url:Lastname", new Attribute(obj.getData().getLastname()));
			proverAttributes.put("url:Town", new Attribute(obj.getData().getTown()));
			storage.addAttributes(username, proverAttributes);
		}
	}

	private CoronaIdentityProof getProof(String proof) {
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			return objectMapper.readValue(proof, CoronaIdentityProof.class);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
}
