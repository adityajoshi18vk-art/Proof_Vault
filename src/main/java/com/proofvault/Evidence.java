package com.proofvault;

import java.time.LocalDateTime;

/**
 * ============================================================================
 * JAVA OOP CONCEPT: ABSTRACT CLASS & ENCAPSULATION
 * ============================================================================
 * Evidence serves as an abstract base class that captures shared state and
 * behaviors for all types of digital forensic evidence.
 *
 * Encapsulation is enforced by marking all fields as private and exposing
 * controlled access via public constructors, getters, and setters.
 */
public abstract class Evidence {

    // Encapsulated private attributes
    private String evidenceId;
    private String fileName;
    private String filePath;
    private String fileType;
    private String sha256Hash;
    private String investigatorName;
    private LocalDateTime registrationTime;

    /**
     * Default constructor (OOP Concept: Constructors).
     */
    public Evidence() {
        this.registrationTime = LocalDateTime.now();
    }

    /**
     * Parameterized constructor to initialize evidence attributes.
     */
    public Evidence(String evidenceId, String fileName, String filePath, String fileType,
                    String sha256Hash, String investigatorName, LocalDateTime registrationTime) {
        this.evidenceId = evidenceId;
        this.fileName = fileName;
        this.filePath = filePath;
        this.fileType = fileType;
        this.sha256Hash = sha256Hash;
        this.investigatorName = investigatorName;
        this.registrationTime = registrationTime != null ? registrationTime : LocalDateTime.now();
    }

    // ========================================================================
    // GETTERS AND SETTERS (OOP Concept: Encapsulation)
    // ========================================================================

    public String getEvidenceId() {
        return evidenceId;
    }

    public void setEvidenceId(String evidenceId) {
        this.evidenceId = evidenceId;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getFileType() {
        return fileType;
    }

    public void setFileType(String fileType) {
        this.fileType = fileType;
    }

    public String getSha256Hash() {
        return sha256Hash;
    }

    public void setSha256Hash(String sha256Hash) {
        this.sha256Hash = sha256Hash;
    }

    public String getInvestigatorName() {
        return investigatorName;
    }

    public void setInvestigatorName(String investigatorName) {
        this.investigatorName = investigatorName;
    }

    public LocalDateTime getRegistrationTime() {
        return registrationTime;
    }

    public void setRegistrationTime(LocalDateTime registrationTime) {
        this.registrationTime = registrationTime;
    }

    /**
     * ========================================================================
     * JAVA OOP CONCEPT: ABSTRACT METHOD & RUNTIME POLYMORPHISM
     * ========================================================================
     * Concrete subclasses (e.g., DocumentEvidence, ImageEvidence) must provide
     * their own implementation of getEvidenceType(). Calling this method on
     * an Evidence reference dynamically dispatches to the subclass implementation.
     *
     * @return category/type identifier of the evidentiary artifact
     */
    public abstract String getEvidenceType();

    /**
     * Displays formatted details of the digital evidence item.
     * Demonstrates polymorphic behavior by invoking getEvidenceType().
     */
    public void displayDetails() {
        System.out.println("----- Evidence Record -----");
        System.out.println("ID:            " + evidenceId);
        System.out.println("Category:      " + getEvidenceType());
        System.out.println("Filename:      " + fileName);
        System.out.println("Storage Path:  " + filePath);
        System.out.println("MIME/Type:     " + fileType);
        System.out.println("SHA-256 Hash:  " + sha256Hash);
        System.out.println("Investigator:  " + investigatorName);
        System.out.println("Registered At: " + registrationTime);
        System.out.println("---------------------------");
    }
}
