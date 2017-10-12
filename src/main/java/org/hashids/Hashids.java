package org.hashids;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Hashids designed for Generating short hashes from numbers (like YouTube and Bitly), obfuscate
 * database IDs, use them as forgotten password hashes, invitation codes, store shard numbers.
 * <p>
 * This is implementation of http://hashids.org v1.0.0 version.
 *
 * This implementation is immutable, thread-safe, no lock is necessary.
 *
 * @author <a href="mailto:fanweixiao@gmail.com">fanweixiao</a>
 * @author <a href="mailto:terciofilho@gmail.com">Tercio Gaudencio Filho</a>
 * @author comtel2000
 * 
 * @since 0.3.3
 */
public class Hashids {
  /**
   * Max number that can be encoded with Hashids.
   */
  public static final long MAX_NUMBER = 9007199254740992L;

  private static final String DEFAULT_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
  private static final String DEFAULT_SEPS = "cfhistuCFHISTU";
  private static final String DEFAULT_SALT = "";

  private static final int DEFAULT_MIN_HASH_LENGTH = 0;
  private static final int MIN_ALPHABET_LENGTH = 16;
  private static final double SEP_DIV = 3.5;
  private static final int GUARD_DIV = 12;

  private final String salt;
  private final int minHashLength;
  private final String alphabet;
  private final String seps;
  private final String guards;
  
  private final String validDecodeChars;
  
  private final Pattern sepsPattern;
  private final Pattern guardPattern;
  
  private boolean verify = true;


  
  public Hashids() {
    this(DEFAULT_SALT);
  }

  public Hashids(String salt) {
    this(salt, 0);
  }

  public Hashids(String salt, int minHashLength) {
    this(salt, minHashLength, DEFAULT_ALPHABET);
  }

  public Hashids(String salt, int minHashLength, String alphabet) {
    this.salt = salt != null ? salt : DEFAULT_SALT;
    this.minHashLength = minHashLength > 0 ? minHashLength : DEFAULT_MIN_HASH_LENGTH;

    final StringBuilder uniqueAlphabet = new StringBuilder();
    for (int i = 0; i < alphabet.length(); i++) {
      if (uniqueAlphabet.indexOf(String.valueOf(alphabet.charAt(i))) == -1) {
        uniqueAlphabet.append(alphabet.charAt(i));
      }
    }

    alphabet = uniqueAlphabet.toString();

    if (alphabet.length() < MIN_ALPHABET_LENGTH) {
      throw new IllegalArgumentException(
          "alphabet must contain at least " + MIN_ALPHABET_LENGTH + " unique characters");
    }

    if (alphabet.contains(" ")) {
      throw new IllegalArgumentException("alphabet cannot contains spaces");
    }

    // seps should contain only characters present in alphabet;
    // alphabet should not contains seps
    String seps = DEFAULT_SEPS;
    for (int i = 0; i < seps.length(); i++) {
      final int j = alphabet.indexOf(seps.charAt(i));
      if (j == -1) {
        seps = seps.substring(0, i) + " " + seps.substring(i + 1);
      } else {
        alphabet = alphabet.substring(0, j) + " " + alphabet.substring(j + 1);
      }
    }

    alphabet = alphabet.replaceAll("\\s+", "");
    seps = seps.replaceAll("\\s+", "");
    seps = Hashids.consistentShuffle(seps, this.salt);

    if ((seps.isEmpty()) || (((float) alphabet.length() / seps.length()) > SEP_DIV)) {
      int seps_len = (int) Math.ceil(alphabet.length() / SEP_DIV);

      if (seps_len == 1) {
        seps_len++;
      }

      if (seps_len > seps.length()) {
        final int diff = seps_len - seps.length();
        seps += alphabet.substring(0, diff);
        alphabet = alphabet.substring(diff);
      } else {
        seps = seps.substring(0, seps_len);
      }
    }

    alphabet = Hashids.consistentShuffle(alphabet, this.salt);
    // use double to round up
    final int guardCount = (int) Math.ceil((double) alphabet.length() / GUARD_DIV);

    String guards;
    if (alphabet.length() < 3) {
      guards = seps.substring(0, guardCount);
      seps = seps.substring(guardCount);
    } else {
      guards = alphabet.substring(0, guardCount);
      alphabet = alphabet.substring(guardCount);
    }
    this.guards = guards;
    this.guardPattern = Pattern.compile("[" + this.guards + "]");
    this.seps = seps;
    this.sepsPattern = Pattern.compile("[" + this.seps + "]");
    this.alphabet = alphabet;

    this.validDecodeChars = this.alphabet + this.guards + this.seps;
  }

  /**
   * Enable or disable verification of encoded value
   * 
   * @param flag enable or disable
   */
  public void setVerifyEnabled(boolean flag) {
	  verify = flag;
  }
  
  /**
   * Encrypt numbers to string
   *
   * @param numbers
   *          the numbers to encrypt
   * @return the encrypt string
   */
  public String encode(long... numbers) {
    if (numbers.length == 0) {
      return "";
    }

    for (final long number : numbers) {
      if (number < 0) {
        return "";
      }
      if (number > MAX_NUMBER) {
        throw new IllegalArgumentException("number can not be greater than " + MAX_NUMBER + "L");
      }
    }
    return this._encode(numbers);
  }

  /**
   * Decrypt string to numbers
   *
   * @param hash
   *          the encrypt string
   * @return decryped numbers
   */
  public long[] decode(String hash) {
    if (hash == null || hash.isEmpty()) {
    	throw new IllegalArgumentException("value must not be null or empty");
    }
    
    int hashLen = hash.length();
    for (int i = 0; i < hashLen; i++) {
      if(validDecodeChars.indexOf(hash.charAt(i)) == -1) {
    	  throw new IllegalArgumentException("value contains invalid chars");
      }
    }

    return this._decode(hash, this.alphabet);
  }

  /**
   * Encrypt hexa to string
   *
   * @param hexa
   *          the hexa to encrypt
   * @return the encrypt string
   */
  public String encodeHex(String hexa) {
    if (!hexa.matches("^[0-9a-fA-F]+$")) {
      throw new IllegalArgumentException("value must be hex");
    }

    final List<Long> matched = new ArrayList<Long>();
    final Matcher matcher = Pattern.compile("[\\w\\W]{1,12}").matcher(hexa);

    while (matcher.find()) {
      matched.add(Long.parseLong("1" + matcher.group(), 16));
    }

    // conversion
    final long[] result = new long[matched.size()];
    for (int i = 0; i < matched.size(); i++) {
      result[i] = matched.get(i);
    }
    return this.encode(result);
  }

  /**
   * Decrypt string to numbers
   *
   * @param hash
   *          the encrypt string
   * @return decryped numbers
   */
  public String decodeHex(String hash) {

    final long[] numbers = this.decode(hash);
    final StringBuilder result = new StringBuilder(numbers.length);
    for (final long number : numbers) {
      result.append(Long.toHexString(number).substring(1));
    }
    return result.toString();
  }

  public static int checkedCast(long value) {
    final int result = (int) value;
    if (result != value) {
      // don't use checkArgument here, to avoid boxing
      throw new IllegalArgumentException("Out of range: " + value);
    }
    return result;
  }

  private String _encode(long... numbers) {
    long numberHashInt = 0;
    for (int i = 0; i < numbers.length; i++) {
      numberHashInt += (numbers[i] % (i + 100));
    }
    String tempAlphabet = this.alphabet;
    final char ret = tempAlphabet.charAt((int) (numberHashInt % tempAlphabet.length()));

    long num;
    long sepsIndex, guardIndex;
    String buffer;
    final StringBuilder retBuilder = new StringBuilder(this.minHashLength);
    retBuilder.append(ret);
    char guard;

    for (int i = 0; i < numbers.length; i++) {
      num = numbers[i];
      buffer = ret + this.salt + tempAlphabet;

      tempAlphabet = Hashids.consistentShuffle(tempAlphabet, buffer.substring(0, tempAlphabet.length()));
      final String last = Hashids.hash(num, tempAlphabet);

      retBuilder.append(last);

      if (i + 1 < numbers.length) {
        if (last.length() > 0) {
          num %= (last.charAt(0) + i);
          sepsIndex = (int) (num % this.seps.length());
        } else {
          sepsIndex = 0;
        }
        retBuilder.append(this.seps.charAt((int) sepsIndex));
      }
    }

    String retValue = retBuilder.toString();
    if (retValue.length() < this.minHashLength) {
      guardIndex = (numberHashInt + (retValue.charAt(0))) % this.guards.length();
      guard = this.guards.charAt((int) guardIndex);

      retValue = guard + retValue;

      if (retValue.length() < this.minHashLength) {
        guardIndex = (numberHashInt + (retValue.charAt(2))) % this.guards.length();
        guard = this.guards.charAt((int) guardIndex);

        retValue += guard;
      }
    }

    final int halfLen = tempAlphabet.length() / 2;
    while (retValue.length() < this.minHashLength) {
      tempAlphabet = Hashids.consistentShuffle(tempAlphabet, tempAlphabet);
      retValue = tempAlphabet.substring(halfLen) + retValue + tempAlphabet.substring(0, halfLen);
      final int excess = retValue.length() - this.minHashLength;
      if (excess > 0) {
        final int start_pos = excess / 2;
        retValue = retValue.substring(start_pos, start_pos + this.minHashLength);
      }
    }

    return retValue;
  }

  private long[] _decode(String hash, String alphabet) {
    final ArrayList<Long> ret = new ArrayList<Long>();
    
    String hashBreakdown = guardPattern.matcher(hash).replaceAll(" ");
    String[] hashArray = hashBreakdown.split(" ");

    int i = (hashArray.length == 3 || hashArray.length == 2) ? 1 : 0;

    if (hashArray.length > 0) {
      hashBreakdown = hashArray[i];
      if (!hashBreakdown.isEmpty()) {
        final char lottery = hashBreakdown.charAt(0);
        hashBreakdown = sepsPattern.matcher(hashBreakdown.substring(1)).replaceAll(" ");
        hashArray = hashBreakdown.split(" ");

        String subHash, buffer;
        for (final String aHashArray : hashArray) {
          subHash = aHashArray;
          buffer = lottery + this.salt + alphabet;
          alphabet = Hashids.consistentShuffle(alphabet, buffer.substring(0, alphabet.length()));
          ret.add(Hashids.unhash(subHash, alphabet));
        }
      }
    }

    // transform from List<Long> to long[]
    long[] arr = new long[ret.size()];
    for (int k = 0; k < arr.length; k++) {
      arr[k] = ret.get(k);
    }

    if (verify && !this.encode(arr).equals(hash)) {
      throw new IllegalStateException("verification failed");
    }

    return arr;
  }

  private static String consistentShuffle(String alphabet, String salt) {
    if (salt.length() <= 0) {
      return alphabet;
    }

    int asc_val, j;
    final char[] tmpArr = alphabet.toCharArray();
    for (int i = tmpArr.length - 1, v = 0, p = 0; i > 0; i--, v++) {
      v %= salt.length();
      asc_val = salt.charAt(v);
      p += asc_val;
      j = (asc_val + v + p) % i;
      final char tmp = tmpArr[j];
      tmpArr[j] = tmpArr[i];
      tmpArr[i] = tmp;
    }

    return new String(tmpArr);
  }

  private static String hash(long in, String alphabet) {
    StringBuilder hash = new StringBuilder();
    final int alphabetLen = alphabet.length();
    long input = in;
    int index;
    do {
      index = (int) (input % alphabetLen);
      if (index >= 0 && index < alphabetLen) {
    	  hash.insert(0, alphabet.charAt(index));
      }
      input /= alphabetLen;
    } while (input > 0);

    return hash.toString();
  }

  private static long unhash(String input, String alphabet) {
    long number = 0, pos;
    int inputLen = input.length();
    int alphabetLen = alphabet.length();
    
    for (int i = 0; i < inputLen; i++) {
      pos = alphabet.indexOf(input.charAt(i));
      number = number * alphabetLen + pos;
    }

    return number;
  }

  /**
   * Get Hashid algorithm version.
   *
   * @return Hashids algorithm version implemented.
   */
  public String getVersion() {
    return "1.0.0";
  }
}
