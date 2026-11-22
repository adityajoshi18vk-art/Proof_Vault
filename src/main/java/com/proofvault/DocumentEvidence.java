package com.proofvault;

import java.time.LocalDateTime;

/**
 * ============================================================================
 * JAVA OOP CONCEPT: INHERITANCE & METHOD OVERRIDING
 * ============================================================================
 * DocumentEvidence extends Evidence, inheriting its attributes and behavior.
 * It provides specialized handling for document files (PDF, DOCX, TXT, etc.).
 */
public class DocumentEvidence extends Evidence {

    /**
     * Default constructor invoking superclass constructor.
     */
    public DocumentEvidence() {
        super();
    }

    /**
     * Parameterized constructor calling the superclass constructor via super().
     */
    public DocumentEvidence(String evidenceId, String fileName, String filePath, String fileType,
                            String sha256Hash, String investigatorName, LocalDateTime registrationTime) {
        super(evidenceId, fileName, filePath, fileType, sha256Hash, investigatorName, registrationTime);
    }

    /**
     * ========================================================================
     * JAVA OOP CONCEPT: METHOD OVERRIDING & RUNTIME POLYMORPHISM
     * ========================================================================
     * Overrides the abstract method defined in Evidence.
     * When referenced as an Evidence object at runtime, calling getEvidenceType()
     * returns "DOCUMENT".
     */
    @Override
    public String getEvidenceType() {
        return "DOCUMENT";
    }
}
