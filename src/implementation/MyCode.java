package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import code.GuiException;
import gui.Constants;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {

	static final String UNSIGNED_OR_SELFSIGNED = "UNSIGNED / SELF-SIGNED";

	private KeyStore localKeyStore;
	private char[] localKeyStorePassword; // sta ciniti s ovim? neophodno je pri
											// setEntry?
	private X509Certificate selectedCertificate;
	private PKCS10CertificationRequest csr = null;
	private String csrKeypairName = null;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
		super(algorithm_conf, extensions_conf);

		localKeyStorePassword = "password".toCharArray(); // lol
		Security.addProvider(new BouncyCastleProvider());
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {

		try {
			localKeyStore = KeyStore.getInstance("pkcs12");
		} catch (KeyStoreException e) {
			e.printStackTrace();
			System.exit(-1);
		}

		try {
			localKeyStore.load(null, null);
		} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}

		Enumeration<String> aliases = null;
		try {
			aliases = localKeyStore.aliases();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}

		return aliases;
	}

	@Override
	public void resetLocalKeystore() {

		try {
			localKeyStore.load(null, null);
		} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}

	}

	@Override
	public int loadKeypair(String keypair_name) {

		final int ERROR = -1;
		final int CERTIFICATE_UNSIGNED = 0;
		final int CERTIFICATE_SIGNED = 1;
		final int TRUSTED_CERTIFICATE = 2;

		try {
			int type = 0;
			final int KEY_ENTRY = 3;
			final int CERTIFICATE_ENTRY = 4;

			X509Certificate cert = null;
			if (localKeyStore.isKeyEntry(keypair_name)) {
				type = KEY_ENTRY;
				PrivateKeyEntry pke = (PrivateKeyEntry) localKeyStore.getEntry(keypair_name,
						new PasswordProtection(localKeyStorePassword));
				cert = (X509Certificate) pke.getCertificate();
			} else if (localKeyStore.isCertificateEntry(keypair_name)) {
				type = CERTIFICATE_ENTRY;
				cert = (X509Certificate) localKeyStore.getCertificate(keypair_name);
			}

			X500Principal subjPrinc = cert.getSubjectX500Principal();
			X500Principal issuerPrinc = cert.getIssuerX500Principal();
			access.setSubject(subjPrinc.getName());
			access.setIssuer(issuerPrinc.getName());
			access.setIssuerSignatureAlgorithm(cert.getSigAlgName());
			if (cert.getPublicKey().getAlgorithm().equals("DSA"))
				access.setPublicKeyParameter(Integer.toString(((DSAPublicKey) cert.getPublicKey()).getY().bitLength()));
			access.setSerialNumber(cert.getSerialNumber().toString());
			access.setNotBefore(cert.getNotBefore());
			access.setNotAfter(cert.getNotAfter());
			int v = cert.getVersion();
			if (v == 3)
				access.setVersion(Constants.V3);
			else
				access.setVersion(Constants.V1);

			if (v == 3) {
				String[] oids = new String[4];
				boolean[] critical = new boolean[4];
				final String akiOid = "2.5.29.35";
				final String skiOid = "2.5.29.14";
				final String ianOid = "2.5.29.18";
				final String ekuOid = "2.5.29.37";
				final Set<String> OID_VALUES = new HashSet<String>(
						Arrays.asList(new String[] { akiOid, skiOid, ianOid, ekuOid }));
				int i = 0;
				if (cert.getCriticalExtensionOIDs() != null)
					for (String oidCrit : cert.getCriticalExtensionOIDs()) {
						if (OID_VALUES.contains(oidCrit)) {
							oids[i] = oidCrit;
							critical[i] = true;
							i++;
						}
					}
				if (cert.getNonCriticalExtensionOIDs() != null)
					for (String oidNonCrit : cert.getNonCriticalExtensionOIDs()) {
						if (OID_VALUES.contains(oidNonCrit)) {
							oids[i] = oidNonCrit;
							critical[i] = false;
							i++;
						}
					}
				for (int j = 0; j < i; j++) {
					switch (oids[j]) {
					case akiOid: {
						byte[] extensionValue = cert.getExtensionValue(oids[j]);
						ASN1OctetString octetString = ASN1OctetString.getInstance(extensionValue);
						AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(octetString.getOctets());
						access.setEnabledKeyIdentifiers(true);
						access.setCritical(Constants.AKID, critical[j]);
						access.setAuthorityKeyID(new DEROctetString(aki.getKeyIdentifier()).toString());
						if (aki.getAuthorityCertIssuer().getNames().length > 0)
							access.setAuthorityIssuer(aki.getAuthorityCertIssuer().getNames()[0].toString()); // getNames()[0]
																												// JER
																												// SE
																												// TAKO
																												// CUVA,
																												// ALI
																												// NE
																												// BI
																												// TREBALO
						access.setAuthoritySerialNumber(aki.getAuthorityCertSerialNumber().toString());
						break;
					}
					case skiOid: {
						byte[] extensionValue = cert.getExtensionValue(oids[j]);
						ASN1OctetString octetString = ASN1OctetString.getInstance(extensionValue);
						SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(octetString.getOctets());
						access.setEnabledKeyIdentifiers(true);
						access.setCritical(Constants.SKID, critical[j]);
						access.setSubjectKeyID(new DEROctetString(ski.getKeyIdentifier()).toString());
						break;
					}
					case ianOid: {
						byte[] extensionValue = cert.getExtensionValue(oids[j]);
						ASN1OctetString octetString = ASN1OctetString.getInstance(extensionValue);
						access.setCritical(Constants.IAN, critical[j]);
						access.setAlternativeName(Constants.IAN, new String(octetString.getOctets()));
						break;
					}
					case ekuOid: {
						byte[] extensionValue = cert.getExtensionValue(oids[j]);
						ASN1OctetString octetString = ASN1OctetString.getInstance(extensionValue);
						access.setCritical(Constants.EKU, critical[j]);
						ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(octetString.getOctets());
						boolean[] keyUsage = new boolean[7];
						if (eku.hasKeyPurposeId(KeyPurposeId.anyExtendedKeyUsage))
							keyUsage[0] = true;
						if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth))
							keyUsage[1] = true;
						if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_clientAuth))
							keyUsage[2] = true;
						if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning))
							keyUsage[3] = true;
						if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection))
							keyUsage[4] = true;
						if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping))
							keyUsage[5] = true;
						if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning))
							keyUsage[6] = true;
						access.setExtendedKeyUsage(keyUsage);
						break;
					}
					}
				}
			}

			if (type == KEY_ENTRY) {
				// odgovarajuci uslovi?
				if (issuerPrinc == null || issuerPrinc.getName().contains(UNSIGNED_OR_SELFSIGNED)
						|| issuerPrinc.getName().equals("") || cert.getSignature() == null) {
					// access.enableSignButton(true);
					// access.enableExportButton(false);
					this.selectedCertificate = null;
					return CERTIFICATE_UNSIGNED;
				} else {
					// access.enableSignButton(false);
					// access.enableExportButton(true);
					this.selectedCertificate = cert;
					return CERTIFICATE_SIGNED;
				}
			} else if (type == CERTIFICATE_ENTRY) {
				// access.enableSignButton(false);
				// access.enableExportButton(true);
				this.selectedCertificate = cert;
				return TRUSTED_CERTIFICATE;
			} else
				return ERROR;

		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
			return ERROR;
		}
	}

	@Override
	public boolean saveKeypair(String keypair_name) {
		if (access.getVersion() != Constants.V3) {
			access.reportError("Only Version 3 is supported!");
			access.setVersion(Constants.V3);
			return false;
		}

		KeyPairGenerator kpg = null;
		try {
			kpg = KeyPairGenerator.getInstance("DSA");
		} catch (NoSuchAlgorithmException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}
		kpg.initialize(Integer.parseInt(access.getPublicKeyParameter()));
		KeyPair kp = kpg.generateKeyPair();

		// JcaX509v3CertificateBuilder cb = null;
		// cb = new JcaX509v3CertificateBuilder(new
		// X500Principal(access.getSubject()),
		// new BigInteger(access.getSerialNumber()), access.getNotBefore(),
		// access.getNotAfter(),
		// new X500Principal(access.getSubject()), kp.getPublic());

		X509v3CertificateBuilder cb = null;
		X500NameBuilder nb = new X500NameBuilder();
		nb.addRDN(X509ObjectIdentifiers.commonName, UNSIGNED_OR_SELFSIGNED);
		X500Name selfSignedX500Name = nb.build();

		try {
			cb = new X509v3CertificateBuilder(selfSignedX500Name, new BigInteger(access.getSerialNumber()),
					access.getNotBefore(), access.getNotAfter(), new X500Name(access.getSubject()),
					SubjectPublicKeyInfoFactory
							.createSubjectPublicKeyInfo(PublicKeyFactory.createKey(kp.getPublic().getEncoded())));
		} catch (IOException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}

		// PRETVARA String[] U String, da li je neophodno drugacije?
		StringBuilder sb = new StringBuilder();
		for (String ian : access.getAlternativeName(Constants.IAN))
			sb.append(ian);
		String ianString = sb.toString();
		if (!ianString.equals("")) {
			ASN1ObjectIdentifier oid = Extension.issuerAlternativeName;
			Extension issuerAlternativeName = new Extension(oid, access.isCritical(Constants.IAN),
					new DEROctetString(ianString.getBytes()));
			try {
				cb.addExtension(issuerAlternativeName);
			} catch (CertIOException e) {
				access.reportError(e);
				e.printStackTrace();
				return false;
			}
		}

		if (access.getEnabledKeyIdentifiers() == true) {
			JcaX509ExtensionUtils extensionUtils = null;
			try {
				extensionUtils = new JcaX509ExtensionUtils();
			} catch (NoSuchAlgorithmException e) {
				access.reportError(e);
				e.printStackTrace();
				return false;
			}
			AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(kp.getPublic(),
					new X500Principal(access.getSubject()), new BigInteger(access.getSerialNumber()));
			SubjectKeyIdentifier ski = extensionUtils.createSubjectKeyIdentifier(kp.getPublic());

			Extension authorityKeyIdentifier;
			Extension subjectKeyIdentifier;
			try {
				authorityKeyIdentifier = new Extension(Extension.authorityKeyIdentifier,
						access.isCritical(Constants.AKID), new DEROctetString(aki));
				subjectKeyIdentifier = new Extension(Extension.subjectKeyIdentifier, access.isCritical(Constants.SKID),
						new DEROctetString(ski));
				// DA LI DA BUDE Constants.SKID ili Constants.AKID kod
				// subjectKeyIdentifier?
			} catch (IOException e) {
				access.reportError(e);
				e.printStackTrace();
				return false;
			}

			try {
				cb.addExtension(authorityKeyIdentifier);
				cb.addExtension(subjectKeyIdentifier);
			} catch (CertIOException e) {
				access.reportError(e);
				e.printStackTrace();
				return false;
			}
		}

		boolean[] ekuValues = access.getExtendedKeyUsage();
		int numOfEKUValues = 0;
		for (boolean f : ekuValues) {
			if (f == true) {
				++numOfEKUValues;
			}
		}
		if (numOfEKUValues != 0) {
			KeyPurposeId[] usages = new KeyPurposeId[numOfEKUValues];
			for (int i = 0, j = 0; i < ekuValues.length; i++) {
				if (ekuValues[i] == true)
					switch (i) {
					case 0:
						usages[j] = KeyPurposeId.getInstance(KeyPurposeId.anyExtendedKeyUsage);
						j++;
						break;
					case 1:
						usages[j] = KeyPurposeId.getInstance(KeyPurposeId.id_kp_serverAuth);
						j++;
						break;
					case 2:
						usages[j] = KeyPurposeId.getInstance(KeyPurposeId.id_kp_clientAuth);
						j++;
						break;
					case 3:
						usages[j] = KeyPurposeId.getInstance(KeyPurposeId.id_kp_codeSigning);
						j++;
						break;
					case 4:
						usages[j] = KeyPurposeId.getInstance(KeyPurposeId.id_kp_emailProtection);
						j++;
						break;
					case 5:
						usages[j] = KeyPurposeId.getInstance(KeyPurposeId.id_kp_timeStamping);
						j++;
						break;
					case 6:
						usages[j] = KeyPurposeId.getInstance(KeyPurposeId.id_kp_OCSPSigning);
						j++;
						break;
					}
			}
			ExtendedKeyUsage eku = new ExtendedKeyUsage(usages);
			try {
				Extension extendedKeyUsage = new Extension(Extension.extendedKeyUsage, access.isCritical(Constants.EKU),
						new DEROctetString(eku));
				cb.addExtension(extendedKeyUsage);
			} catch (IOException e) {
				access.reportError(e);
				e.printStackTrace();
				return false;
			}
		}

		X509CertificateHolder certHolder = null;
		try {
			// X9ObjectIdentifiers.id_dsa_with_sha1,
			// OIWObjectIdentifiers.dsaWithSHA1
			// certHolder = cb
			// .build((new BcDSAContentSignerBuilder(new
			// AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa_with_sha1),
			// new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)))
			// .build(PrivateKeyFactory.createKey(kp.getPrivate().getEncoded())));
			certHolder = cb.build(new JcaContentSignerBuilder(access.getPublicKeySignatureAlgorithm()).setProvider("BC")
					.build(kp.getPrivate()));
		} catch (OperatorCreationException /* | IOException */ e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}

		X509Certificate cert = null;
		try {
			cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
		} catch (CertificateException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}
		Certificate[] certChain = { cert };

		PrivateKeyEntry pke = new PrivateKeyEntry(kp.getPrivate(), certChain);
		try {
			localKeyStore.setEntry(keypair_name, pke, new PasswordProtection(localKeyStorePassword));
			// localKeyStore.setKeyEntry(keypair_name, kp.getPrivate(),
			// localKeyStorePassword, null);
		} catch (KeyStoreException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}

		return true;
	}

	@Override
	public boolean removeKeypair(String keypair_name) {

		try {
			localKeyStore.deleteEntry(keypair_name);
		} catch (KeyStoreException e) {
			return false;
		}

		return true;
	}

	@Override
	public boolean importKeypair(String keypair_name, String file, String password) {

		KeyStore fileKeyStore = null;
		try {
			fileKeyStore = KeyStore.getInstance("pkcs12");
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return false;
		}

		FileInputStream fis = null;
		try {
			fis = new FileInputStream(file);
			fileKeyStore.load(fis, password.toCharArray());
			Entry entry = fileKeyStore.getEntry(keypair_name, new PasswordProtection(password.toCharArray()));
			if (entry instanceof SecretKeyEntry)
				return false;
			localKeyStore.setEntry(keypair_name, entry, new PasswordProtection(localKeyStorePassword));
		} catch (NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableEntryException
				| KeyStoreException e) {
			access.reportError(e);
			return false;

		} finally {
			if (fis != null)
				try {
					fis.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
		}

		return true;
	}

	@Override
	public boolean exportKeypair(String keypair_name, String file, String password) {

		PrivateKeyEntry pke = null;
		// try {
		// Key key = localKeyStore.getKey(keypair_name, localKeyStorePassword);
		// if (key == null || !(key instanceof PrivateKey)) {
		// access.reportError("Key is not PrivateKey or is nonexistent.");
		// return false;
		// }
		// PrivateKey pk = (PrivateKey) key;
		// pke = new PrivateKeyEntry(pk,
		// localKeyStore.getCertificateChain(keypair_name));
		// } catch (UnrecoverableKeyException | KeyStoreException |
		// NoSuchAlgorithmException e) {
		// access.reportError(e);
		// return false;
		// }
		try {
			if (localKeyStore.isKeyEntry(keypair_name))
				pke = (PrivateKeyEntry) localKeyStore.getEntry(keypair_name,
						new PasswordProtection(localKeyStorePassword));
			else
				return false;
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e1) {
			access.reportError(e1);
			e1.printStackTrace();
			return false;
		}

		KeyStore exportKeyStore = null;
		try {
			exportKeyStore = KeyStore.getInstance("pkcs12");
			exportKeyStore.load(null, null);
			// exportKeyStore.setKeyEntry(keypair_name, pke.getPrivateKey(),
			// password.toCharArray(),
			// pke.getCertificateChain());
			exportKeyStore.setEntry(keypair_name, pke, new PasswordProtection(password.toCharArray()));
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}

		if (!file.endsWith(".p12"))
			file = file.concat(".p12"); // potrebno?

		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(file);
			exportKeyStore.store(fos, password.toCharArray());
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		} finally {
			if (fos != null)
				try {
					fos.close();
				} catch (IOException e) {
					access.reportError(e);
					e.printStackTrace();
				}
		}

		return true;
	}

	@Override
	public boolean signCertificate(String issuer, String algorithm) {

		PrivateKeyEntry issuerPKE = null;
		try {
			issuerPKE = (PrivateKeyEntry) localKeyStore.getEntry(issuer, new PasswordProtection(localKeyStorePassword));
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}

		X509Certificate issuerCert = (X509Certificate) issuerPKE.getCertificate();
		// MORA OVAKO DA SE NE BI MENJAO REDOSLED STAVKI U STRINGU
		X500Name issuerX500 = new X500Name(RFC4519Style.INSTANCE, issuerCert.getSubjectX500Principal().getName());

		X509v3CertificateBuilder cb = null;
		cb = new X509v3CertificateBuilder(issuerX500, new BigInteger(access.getSerialNumber()), access.getNotBefore(),
				access.getNotAfter(), csr.getSubject(), csr.getSubjectPublicKeyInfo());

		Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
		if (attributes.length > 0) {
			Extensions ext = Extensions.getInstance(attributes[0].getAttributeValues()[0]);
			Extension aki = ext.getExtension(Extension.authorityKeyIdentifier);
			Extension ski = ext.getExtension(Extension.subjectKeyIdentifier);
			Extension ian = ext.getExtension(Extension.issuerAlternativeName);
			Extension eku = ext.getExtension(Extension.extendedKeyUsage);
			if (aki != null) {
				JcaX509ExtensionUtils extensionUtils;
				try {
					extensionUtils = new JcaX509ExtensionUtils();
				} catch (NoSuchAlgorithmException e) {
					access.reportError(e);
					e.printStackTrace();
					return false;
				}
				AuthorityKeyIdentifier authKeyId = extensionUtils.createAuthorityKeyIdentifier(
						issuerCert.getPublicKey(), issuerCert.getSubjectX500Principal(),
						new BigInteger(access.getSerialNumber()));
				try {
					aki = new Extension(Extension.authorityKeyIdentifier, access.isCritical(Constants.AKID),
							new DEROctetString(authKeyId));
				} catch (IOException e) {
					access.reportError(e);
					e.printStackTrace();
					return false;
				}
			}
			try {
				if (aki != null)
					cb.addExtension(aki);
				if (ski != null)
					cb.addExtension(ski);
				if (ian != null)
					cb.addExtension(ian);
				if (eku != null)
					cb.addExtension(eku);
			} catch (CertIOException e) {
				access.reportError(e);
				e.printStackTrace();
				return false;
			}
		}

		X509CertificateHolder subjectCertHolder = null;
		try {
			// NEMA RIPEMD ALGORITAM NA OVAJ NACIN ?!
			subjectCertHolder = cb
					.build(new JcaContentSignerBuilder(algorithm).setProvider("BC").build(issuerPKE.getPrivateKey()));
			// AlgorithmIdentifier sigAlgId = new
			// DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
			// AlgorithmIdentifier digAlgId = new
			// DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
			// BcContentSignerBuilder csb = new BcContentSignerBuilder(sigAlgId,
			// digAlgId);
			// AsymmetricKeyParameter issuerPrivateKey = PrivateKeyFactory
			// .createKey(issuerPKE.getPrivateKey().getEncoded());
			// ContentSigner cs = csb.build(issuerPrivateKey);
			// subjectCertHolder = cb.build(cs);
		} catch (OperatorCreationException /* | IOException */ e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}

		X509Certificate subjectCert = null;
		try {
			subjectCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(subjectCertHolder);
		} catch (CertificateException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}
		X509Certificate[] chain = { subjectCert/* , issuerCert */ };

		PrivateKeyEntry oldSubjectPKE;
		try {
			oldSubjectPKE = (PrivateKeyEntry) localKeyStore.getEntry(csrKeypairName,
					new PasswordProtection(localKeyStorePassword));
			// localKeyStore.setKeyEntry(csrKeypairName,
			// oldSubjectPKE.getPrivateKey(), localKeyStorePassword, chain);
			PrivateKeyEntry newSubjectPKE = new PrivateKeyEntry(oldSubjectPKE.getPrivateKey(), chain);
			localKeyStore.setEntry(csrKeypairName, newSubjectPKE, new PasswordProtection(localKeyStorePassword));
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}

		// Signature sig = null;
		// // byte[] sigBytes = null;
		// try {
		// sig = Signature.getInstance(algorithm);
		// sig.initSign(issuerPKE.getPrivateKey());
		// sig.update(subjectCert.getEncoded());
		// /* sigBytes = */sig.sign();
		// } catch (NoSuchAlgorithmException e) {
		// access.reportError(e);
		// e.printStackTrace();
		// return false;
		// } catch (InvalidKeyException e) {
		// access.reportError(e);
		// e.printStackTrace();
		// return false;
		// } catch (CertificateEncodingException e) {
		// access.reportError(e);
		// e.printStackTrace();
		// return false;
		// } catch (SignatureException e) {
		// access.reportError(e);
		// e.printStackTrace();
		// return false;
		// }

		return true;
	}

	@Override
	public boolean importCertificate(File file, String keypair_name) {

		CertificateFactory cf = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			access.reportError(e);
			return false;
		}

		FileInputStream fis = null;
		try {
			fis = new FileInputStream(file);
			Certificate cert = cf.generateCertificate(fis);
			localKeyStore.setCertificateEntry(keypair_name, cert);
		} catch (FileNotFoundException | CertificateException | KeyStoreException e) {
			access.reportError(e);
			return false;
		} finally {
			if (fis != null)
				try {
					fis.close();
				} catch (IOException e) {
					access.reportError(e);
					e.printStackTrace();
				}
		}

		return true;
	}

	@Override
	public boolean exportCertificate(File file, int encoding) {

		if (this.selectedCertificate != null) {

			FileOutputStream fos = null;
			try {
				fos = new FileOutputStream(file);
				if (encoding == Constants.DER) {
					fos.write(this.selectedCertificate.getEncoded());
				} else if (encoding == Constants.PEM) {
					fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
					fos.write(Base64.getEncoder().encode(this.selectedCertificate.getEncoded()));
					fos.write("\n-----END CERTIFICATE-----\n".getBytes());
				} else {
					access.reportError("Nonexistent encoding.");
					return false;
				}
			} catch (FileNotFoundException | CertificateEncodingException e) {
				access.reportError(e);
				return false;
			} catch (IOException e) { // lakse debagovanje?
				access.reportError(e);
				return false;
			} finally {
				if (fos != null)
					try {
						fos.close();
					} catch (IOException e) {
						access.reportError(e);
						e.printStackTrace();
					}
			}

			if (!file.getName().endsWith(".cer")) // potrebno?
				if (file.renameTo(new File(file.getPath().concat(".cer"))) == false)
					access.reportError("The extension of the exported file is not .cer!");

		} else
			return false;

		return true;
	}

	@Override
	public String getIssuer(String keypair_name) {

		X509Certificate cert = null;
		try {
			Entry entry = localKeyStore.getEntry(keypair_name, new PasswordProtection(localKeyStorePassword));
			if (entry instanceof PrivateKeyEntry)
				cert = (X509Certificate) ((PrivateKeyEntry) entry).getCertificate();
			else if (entry instanceof TrustedCertificateEntry)
				cert = (X509Certificate) ((TrustedCertificateEntry) entry).getTrustedCertificate();
			else
				return null;
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
			access.reportError(e);
			e.printStackTrace();
			return null;
		}

		return cert.getIssuerX500Principal().getName();
	}

	@Override
	public String getIssuerPublicKeyAlgorithm(String keypair_name) {
		try {
			PrivateKeyEntry issuerPKE = (PrivateKeyEntry) localKeyStore.getEntry(keypair_name,
					new PasswordProtection(localKeyStorePassword));
			X509Certificate cert = (X509Certificate) issuerPKE.getCertificate();
			return cert.getPublicKey().getAlgorithm();
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
			access.reportError(e);
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public int getRSAKeyLength(String keypair_name) {
		// RSA NOT USED
		return 0;
	}

	@Override
	public List<String> getIssuers(String keypair_name) {

		Enumeration<String> e = null;
		try {
			e = localKeyStore.aliases();
		} catch (KeyStoreException e1) {
			access.reportError(e1);
			e1.printStackTrace();
			return null;
		}

		List<String> l = new LinkedList<String>();
		while (e.hasMoreElements()) {
			try {
				String elem = e.nextElement();
				if (localKeyStore.isKeyEntry(elem) && !elem.equals(keypair_name))
					l.add(elem);
			} catch (KeyStoreException e1) {
				access.reportError(e1);
				e1.printStackTrace();
				return null;
			}
		}

		return l;
	}

	@Override
	public boolean generateCSR(String keypair_name) {
		// nema potrebe za cast jer ce uvek da se poziva za PrivateKeyEntry?
		PrivateKeyEntry pke = null;
		try {
			pke = (PrivateKeyEntry) localKeyStore.getEntry(keypair_name, new PasswordProtection(localKeyStorePassword));
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}
		X509Certificate cert = (X509Certificate) pke.getCertificate();
		JcaPKCS10CertificationRequestBuilder csrb = new JcaPKCS10CertificationRequestBuilder(
				cert.getSubjectX500Principal(), cert.getPublicKey());

		X509CertificateHolder certHolder;
		try {
			certHolder = new X509CertificateHolder(cert.getEncoded());
		} catch (CertificateEncodingException | IOException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}
		Extensions ext = certHolder.getExtensions();
		if (ext != null)
			csrb.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, ext);

		try {
			this.csr = csrb.build(new JcaContentSignerBuilder(access.getPublicKeySignatureAlgorithm()).setProvider("BC")
					.build(pke.getPrivateKey()));
		} catch (OperatorCreationException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}

		this.csrKeypairName = keypair_name;

		return true;
	}
}
