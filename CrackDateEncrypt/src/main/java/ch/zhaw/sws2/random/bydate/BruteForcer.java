package ch.zhaw.sws2.random.bydate;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Comparator;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * <p>
 * BruteForcer to brute force the "Netscape encryption". Multiple BruteForcers
 * can be used and run in parallel to search different parts of the keyspace at
 * the same time. Bruteforcing stops when the assigned keyspace has been
 * searched or when one of the BruteForcers finds a candidate that is considered
 * "good enough" based on the rating of the candidate and a threshold for the
 * rating.
 * </p>
 * 
 * <p>
 * It keeps track of promising candidates
 * </p>
 * 
 * @author Bernhard Tellenbach &lt;tebe@zhaw.ch&gt;
 * @version 1.0
 * @date 2016-03-06
 *
 */
public class BruteForcer {
	private static final double LN2 = Math.log(2.0);
	private static AtomicBoolean isContinueSearch = new AtomicBoolean(true);
	private TreeSet<Candidate> set = new TreeSet<>(Comparator.comparingDouble(Candidate::getRating));
	private byte[] decryptedContent = new byte[Crack.DECRYPT_MAX_BYTES];

	private static final double RATING_THRESHOLD_TO_STOP_SEARCHING = -900/* TODO */;

	private MyFakeSystemImpl system;
	private NetscapeKeygen keygen;
	private String cipherSpec;
	private double currentMinRating = Double.MAX_VALUE;
	private ZonedDateTime date;
	private long usecOffset;

	/* TODO: Constructor, additional attributes and helper functions (if any) */
	public BruteForcer(ZonedDateTime date, String cipherSpec) {
		this.date = date;
		this.cipherSpec = cipherSpec;
	}

	private static String getCipherAlgorithmFromSpec(String cipherSpec) {
		return cipherSpec.split("/")[0];
	}

	public Candidate getBestCandidate() {
		return set.first();
	}

	public void run(byte[] encryptedData) throws BadPaddingException {
		long[][] zoneOffset = { { 6, 0 }, { 7, 30 }, { 8, 0 }, { 8, 30 }, { 9, 0 } };
		usecOffset = 0;
		boolean cont = true;
		for (long[] offset : zoneOffset) {
			if (cont) {
				while (usecOffset < Constants.USECS_PER_SECOND && cont) {
					ZonedDateTime offsetDate = date.plusHours(offset[0]).plusMinutes(offset[1]);
					system = new MyFakeSystemImpl(offsetDate.toEpochSecond() * Constants.USECS_PER_SECOND + usecOffset,
							date.getZone());
					keygen = new NetscapeKeygen(system, getCipherAlgorithmFromSpec(cipherSpec));
					decrypt(encryptedData);
					cont = updateRating(cont);

					usecOffset++;
				}
			}
		}

	}

	private boolean updateRating(boolean continueSearch) {
		double rating = getRating();
		if (rating < currentMinRating) {
			currentMinRating = rating;
			set.add(new Candidate(system, decryptedContent, rating));
			if (rating < RATING_THRESHOLD_TO_STOP_SEARCHING) {
				continueSearch = false;
				isContinueSearch.set(false);
			}
		}
		return continueSearch;
	}

	/**
	 * Calculates a metric representing how "likely" the "decrypted" data is
	 * indeed the plaintext
	 * 
	 * @return rating
	 */
	private double getRating() {
		String pattern = "[a-zA-Z0-9\\s]*";
		String decryptedContentString = new String(decryptedContent);
		int length = decryptedContentString.length();
		String strBytes = decryptedContentString.replaceAll(pattern, "");
		int length2 = strBytes.length();
		double rating = (length - length2) * -1;
		return rating;

	}

	private void decrypt(byte[] encryptedData) throws BadPaddingException {
		Cipher cipher;
		try {
			keygen.makeKey();
			cipher = Cipher.getInstance(cipherSpec);
			AlgorithmParameters algParam = keygen.getAlgorithmParameters();
			algParam.init(new IvParameterSpec(keygen.getIv()));

			SecretKeySpec skeySpec = keygen.getSecretKeySpec();
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, algParam);

			cipher.update(encryptedData, 0, encryptedData.length, decryptedContent, 0);

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidParameterSpecException | InvalidKeyException
				| InvalidAlgorithmParameterException | ShortBufferException e) {
			throw new IllegalStateException(e);
		}
	}
}