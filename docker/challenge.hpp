#ifndef challenge
#define challenge

#include <stdio.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <string>
#include <libcryptosec/Signer.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/RSAPublicKey.h>
#include <libcryptosec/RSAPrivateKey.h>
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/RSAKeyPair.h>
#include <certificate/RDNSequence.h>
#include <certificate/CertificateRequest.h>
#include <certificate/Extension.h>
#include <certificate/BasicConstraintsExtension.h>
#include <certificate/KeyUsageExtension.h>
#include <certificate/ExtendedKeyUsageExtension.h>
#include <certificate/SubjectKeyIdentifierExtension.h>
#include <certificate/AuthorityKeyIdentifierExtension.h>
#include <certificate/SubjectAlternativeNameExtension.h>
using std::string;

class CA {// Certificate Authority
private:
    CertificateRequest ca = CertificateRequest();
    PrivateKey* chavePrivada;
    PublicKey* chavePublica;

public:
    CA(string nome){
        // chaves
        RSAKeyPair* parChaves = new RSAKeyPair(2048);
        chavePrivada = parChaves->getPrivateKey();
        chavePublica = parChaves->getPublicKey();
        ca.setPublicKey(*chavePublica);

        // extensoes
        vector<Extension *> extensoes;

        BasicConstraintsExtension *bce = new BasicConstraintsExtension();
        bce->setCa(true);
        bce->setCritical(true);
        bce->setPathLen(2);
        Extension e1 = Extension(bce->getX509Extension());
        extensoes.push_back(&e1);

        KeyUsageExtension *kue = new KeyUsageExtension();
        kue->setUsage(KeyUsageExtension::CRL_SIGN, true);
        kue->setUsage(KeyUsageExtension::KEY_CERT_SIGN, true);
        kue->setUsage(KeyUsageExtension::DIGITAL_SIGNATURE, true);
        kue->setCritical(true);
        Extension e2 = Extension(kue->getX509Extension());
        extensoes.push_back(&e2);

        ca.addExtensions(extensoes);

        // add subject
        RDNSequence rdn = RDNSequence();
        rdn.addEntry(RDNSequence::COMMON_NAME, nome);
        ca.setSubject(rdn);

        // auto assinatura
        autoAssinar();
    }

    // getters e setters
    CertificateRequest getCa () const {
        return ca;
    }
    PrivateKey* getChavePrivada() const {
        return chavePrivada;
    }
    PublicKey* getChavePublica() const {
        return chavePublica;
    }
    string getNome(){
        return ca.getSubject().getEntries(RDNSequence::COMMON_NAME)[0];
    }

    // outros metodos
    bool estaAssinado() {
        return ca.isSigned();
    }
    void autoAssinar() {
        MessageDigest::Algorithm algorithm = MessageDigest::SHA256;
        ca.sign(*(this->chavePrivada), algorithm);
    }
};

class Certificado {// Digital Certificate
private:
    CertificateRequest certificado = CertificateRequest();
    PublicKey* chavePublica;

public:
    Certificado(string cpf, string nome, PublicKey* chavePublica){

        // extensoes
        vector<Extension *> extensoes;

        BasicConstraintsExtension *bce = new BasicConstraintsExtension();
        bce->setCa(false);
        Extension e1 = Extension(bce->getX509Extension());
        extensoes.push_back(&e1);

        KeyUsageExtension *kue =  new KeyUsageExtension();
        kue->setUsage(KeyUsageExtension::DIGITAL_SIGNATURE, true);
        kue->setUsage(KeyUsageExtension::NON_REPUDIATION, true);
        Extension e2 = Extension(kue->getX509Extension());
        extensoes.push_back(&e2);

        certificado.addExtensions(extensoes);

        // chave publica
        this->chavePublica = chavePublica;
        certificado.setPublicKey(*(this->chavePublica));

        //subject
        RDNSequence subject = RDNSequence();
        subject.addEntry(RDNSequence::COMMON_NAME, nome);
        subject.addEntry(RDNSequence::SERIAL_NUMBER, cpf);
        certificado.setSubject(subject);
    }

    // getters e setters
    CertificateRequest getCertificado() const {
        return certificado;
    }
    PublicKey* getChavePublica() const {
        return chavePublica;
    }
    string getNome(){
        return certificado.getSubject().getEntries(RDNSequence::COMMON_NAME)[0];
    }
    string getCpf(){
        return certificado.getSubject().getEntries(RDNSequence::SERIAL_NUMBER)[0];
    }
    
    // outros metodos
    bool estaAssinado() {
        return this->certificado.isSigned();
    }
    void assinar(CA ca) {
        MessageDigest::Algorithm algorithm = MessageDigest::SHA256;
        certificado.sign(*(ca.getChavePrivada()), algorithm);
    }
};

class ContainerCertificados {// Gerenciador de Certificados
private:
    vector<Certificado *> certificados;
    
public:
    // getters e setters
    vector<Certificado *> getCertificados () {
        return certificados;
    }
    void setContainerCertificados(vector<Certificado *> certficados){
        this->certificados = certficados;
    }

    // outros metodos
    Certificado* getCertificado(const string& cpf){
        for (unsigned i {0}; i < certificados.size(); i++) {
            if (certificados[i]->getCpf()==cpf){
                return certificados[i];
            }
        }
        return NULL;
    }
    void removerCertificado(string cpf) {
        for (unsigned i = 0; i < certificados.size(); i++) {
            if (certificados[i]->getCpf() == cpf) {
                delete certificados[i];
                certificados.erase(certificados.begin() + i);
                return;
            }
        }
    }
    void addCertificado(Certificado* certificado) {
        if(!getCertificado(certificado->getCpf())){
            certificados.push_back(certificado);
        }
    }
    // busca os certificates requests
    vector<Certificado *> getRequests() {
        vector<Certificado *> requests;
        for (std::vector<Certificado*>::iterator it = certificados.begin(); it != certificados.end(); ++it) {
            if (!(*it)->estaAssinado()) {
                requests.push_back(*it);
            }
        }
        return requests;

    }
    // busca os digital certificates
    vector<Certificado *> getCertificates() {
        vector<Certificado *> certificates;
        for (std::vector<Certificado*>::iterator it = certificados.begin(); it != certificados.end(); ++it) {
            if ((*it)->estaAssinado()) {
                certificates.push_back(*it);
            }
        }
        return certificates;

    }
};

class Pessoa {// Operador da Usina
private:
    string nome;
    string senha;
    RSAKeyPair* parChaves;
    PrivateKey* chavePrivada;
    PublicKey* chavePublica;
    Certificado* certificado;

public:
    string cpf;
    // construtor
    Pessoa(string cpf, string nome, string senha) : cpf(cpf), nome(nome), senha(senha) {
        parChaves = new RSAKeyPair(2048);
        chavePrivada = parChaves->getPrivateKey();
        chavePublica = parChaves->getPublicKey();
    }

    // getters e setters
    string getCpf () const {
        return cpf;
    }
    void setCpf(string novoCpf) {
        cpf = novoCpf;
    }
    string getNome () const {
        return nome;
    }
    void setNome (string novoNome) {
        nome = novoNome;
    }
    string getSenha(){
        return senha;
    }
    void setSenha(string novaSenha){
        senha = novaSenha;
    }
    RSAKeyPair* getParChaves() const {
        return parChaves;
    } 
    PrivateKey* getChavePrivada() const {
        return chavePrivada;
    }
    PublicKey* getChavePublica() const {
        return chavePublica;
    }
    Certificado* getCertificado() {
        return certificado;
    }
    void addCertificado(Certificado* novoCertificado) {
        certificado = novoCertificado;
    }
    void removerCertificado(){
        certificado = NULL;
    }

    // destrutor
    ~Pessoa() {
        delete parChaves;
        delete chavePublica;
        delete chavePrivada;
    }
};

class ContainerPessoas {// Gerenciador de Pessoas
private:
    vector<Pessoa *> pessoas;

public:
    // getter e setter
    string getCpf(Pessoa* Pessoa){
        return Pessoa->getCpf();
    }
    vector<Pessoa *> getPessoas() {
        return pessoas;
    }
    void setPessoas(vector<Pessoa *> pessoas){
        this->pessoas = pessoas;
    }

    // outros metodos
    Pessoa* getPessoa(const string& cpf){
        for (unsigned i {0}; i < pessoas.size(); i++) {
            if (pessoas[i]->cpf == cpf){
                return pessoas[i];
            }
        }
        return NULL;
    }
    void removerPessoa(string cpf) {
        for (unsigned i = 0; i < pessoas.size(); i++) {
            if (pessoas[i]->getCpf() == cpf) {
                delete pessoas[i];
                pessoas.erase(pessoas.begin() + i);

                return;
            }
        }
    }
    void adicionarPessoa(Pessoa* Pessoa) {
        if(!getPessoa(Pessoa->getCpf())){
            pessoas.push_back(Pessoa);
        }
    }
    vector<Pessoa *> sortPessoas() {

        vector<string> ordem;

        for (std::vector<Pessoa*>::iterator it = pessoas.begin(); it != pessoas.end(); ++it) {
            Pessoa* Pessoa = *it;
            ordem.push_back(Pessoa->getCpf());
        }
        std::sort(ordem.begin(), ordem.end());

        
        vector<Pessoa *> container;
        for (std::vector<std::string>::iterator it = ordem.begin(); it != ordem.end(); ++it) {
            std::string cpf = *it;

            for (unsigned i {0}; i < pessoas.size(); i++) {
                if (pessoas[i]->getCertificado()->getCpf()==cpf){
                    container.push_back(pessoas[i]);
                    break;
                }
            }

        }
        return container;
    }
    vector<PrivateKey*> getChavesPrivadas() {
        vector<PrivateKey*> chavesPrivadas;

        for (std::vector<Pessoa*>::iterator it = pessoas.begin(); it != pessoas.end(); ++it) {
            Pessoa* Pessoa = *it;
            PrivateKey* chavePrivada = Pessoa->getChavePrivada();
            chavesPrivadas.push_back(chavePrivada);
        }
        
        return chavesPrivadas;
    }
    vector<PublicKey*> getChavesPublicas() {
        vector<PublicKey*> chavesPublicas;

        for (std::vector<Pessoa*>::iterator it = pessoas.begin(); it != pessoas.end(); ++it) {
            Pessoa* Pessoa = *it;
            PublicKey* chavePublica = Pessoa->getChavePublica();
            chavesPublicas.push_back(chavePublica);
        }
        
        return chavesPublicas;
    }
};

class PKI { // Public Key Infrastructure: Hierarchical Trust Model
private:
    CA ca = CA("Root CA"); // Certificate Authority
    ContainerCertificados certificados;
    ContainerPessoas pessoas;
    ContainerPessoas desligadores;

public:
    // CA
    CA getCa(){
        return ca;
    }

    // Pessoas
    ContainerPessoas getPessoas(){
        return pessoas;
    }
    void adicionarPessoa(string cpf, string nome, string senha) {
        if(!pessoas.getPessoa(cpf)){
            Pessoa* pessoa = new Pessoa(cpf, nome, senha);
            addCertificado(pessoa);
            pessoas.adicionarPessoa(pessoa);
        }
    }
    void removerPessoa(const string& cpf) {
        pessoas.removerPessoa(cpf);
        certificados.removerCertificado(cpf);
    }
    void sortPessoas(){
        pessoas.setPessoas(pessoas.sortPessoas());
    }

    // Desligadores
    ContainerPessoas getDesligadores(){
        return desligadores;
    }
    void adicionarDesligador(string cpf, string senha) {
        if((pessoas.getPessoa(cpf)!=NULL)and(pessoas.getPessoa(cpf)->getSenha() == senha)){
            desligadores.adicionarPessoa(pessoas.getPessoa(cpf));
        }
    }
    void removerDesligador(const string& cpf) {
        desligadores.removerPessoa(cpf);
    }
    void sortDesligadores(){
        desligadores.setPessoas(desligadores.sortPessoas());
    }

    // Certificados
    ContainerCertificados getCertificados(){
        return certificados;
    }
    void addCertificado(Pessoa* Pessoa) {

        if (!certificados.getCertificado(Pessoa->getCpf())){
            Certificado* certificado = new Certificado(Pessoa->getCpf(), Pessoa->getNome(), Pessoa->getChavePublica()); 
            certificados.addCertificado(certificado);
            Pessoa->addCertificado(certificado);
            assinar(Pessoa->getCpf());
        }
    }
    void removerCertificado(const string& cpf) {
        certificados.removerCertificado(cpf);
        pessoas.getPessoa(cpf)->removerCertificado();
    }
    void certificarPessoas(){
        for (Pessoa* pessoa : pessoas.getPessoas()){
            addCertificado(pessoa);
        }
    }
    void assinar(const string& cpf){
        if (pessoas.getPessoa(cpf) != NULL){
            pessoas.getPessoa(cpf)->getCertificado()->assinar(ca);
        }
    }
    void assinarPessoas(){
        for (Certificado* certificado : certificados.getRequests()){
            assinar(certificado->getCpf());
        }
    }

    // 
};

class SignerManager{ // Gerenciador de Assiaturas
private:
    MessageDigest::Algorithm algorithm = MessageDigest::SHA256;
    vector<ByteArray> assinaturas;
    vector<PrivateKey *> chavesPrivadas;
    vector<PublicKey *> chavesPublicas;
    ByteArray hash;

public:
    SignerManager(string nomeArquivo){
        hash = extrairArquivo(nomeArquivo);
    }

    // getters e setters
    vector<ByteArray> getAssinaturas() {
        return assinaturas;
    }
    vector<PrivateKey *> getChavesPrivadas(){
        return chavesPrivadas;
    }
    void setChavesPrivadas(vector<PrivateKey *> novasChavesPrivadas){
        chavesPrivadas = novasChavesPrivadas;
    }
    vector<PublicKey *> getChavesPublicas(){
        return chavesPublicas;
    }
    void setChavesPublicas(vector<PublicKey *> novasChavesPublicas){
        chavesPublicas = novasChavesPublicas;
    }

    // assino com as chaves privadas
    void assinar() {
        assinaturas.resize(0);
        for (size_t i = 0; i < chavesPrivadas.size(); ++i) {
            PrivateKey* key = chavesPrivadas[i];
            ByteArray assinatura = Signer::sign(*key, hash, algorithm);
            assinaturas.push_back(assinatura);
        }
    }

    // verifico com as chaves publicas
    bool verificar() {
        if (chavesPublicas.size() != assinaturas.size()) {
            return false;
        }
        for (size_t i = 0; i < chavesPublicas.size(); ++i) {
            if (!Signer::verify(*chavesPublicas[i], assinaturas[i], hash, algorithm)) {
                return false;
            }
        }
        return true;
    }

    // Extraindo o hash do pdf
    ByteArray extrairArquivo(string nomeArquivo){
        // abrindo arquivo
        std::ifstream arquivo(nomeArquivo.c_str(), std::ios::binary);
        if (!arquivo) {
            std::cerr << "Erro ao abrir o arquivo PDF" << std::endl;
            // assumo pdf aleatorio
        }

        // extraindo arquivo
        std::ostringstream buffer;

        char ch;
        while (arquivo.get(ch)) {
            buffer.put(ch);
        }
        arquivo.close();

        // arquivo em array de bytes
        ByteArray byteArray(&buffer);
        
        // Hash
        MessageDigest messageDigest = MessageDigest(MessageDigest::SHA256);
        ByteArray hash = messageDigest.doFinal(byteArray);

        return hash;
    }
};

class Controle{ // Sistema Central
private:
    SignerManager* signerManager; // gerenciador de assinaturas
    PKI pki; // Public Key Infrastructure
    
public:
    // contrucao
    Controle(string nomeArquivo) {
        signerManager = new SignerManager(nomeArquivo);
        pki = PKI();
    }

    //getters
    SignerManager getSignerManager(){
        return *signerManager;
    }
    PKI getPki(){
        return pki;
    }

    // chaves privadas de todos os funcionarios
    vector<PrivateKey *> getChavesPrivadas(){
        vector<PrivateKey *> chavesPrivadas = pki.getPessoas().getChavesPrivadas();
        return chavesPrivadas;
    }

    // chaves publicas dos desligadores
    vector<PublicKey *> getChavesPublicas(){
        vector<PublicKey *> chavesPublicas = pki.getDesligadores().getChavesPublicas();
        return chavesPublicas;
    }

    // ordena e assina
    void atualizar(){
        pki.sortPessoas();
        signerManager->setChavesPrivadas(getChavesPrivadas());
        pki.sortDesligadores();
        signerManager->setChavesPublicas(getChavesPublicas());

        signerManager->assinar();
    }

    void adicionarPessoa(string cpf, string nome, string senha){
        pki.adicionarPessoa(cpf, nome, senha);
        atualizar();
    }
    void removerPessoa(string cpf){
        pki.removerPessoa(cpf);
        atualizar();
    }
    void adicionarDesligador(string cpf, string senha){
        pki.adicionarDesligador(cpf, senha);
        atualizar();
    }
    void removerDesligador(string cpf){
        pki.removerDesligador(cpf);
        atualizar();
    }
    
    // Tentativa de desligamento
    string desligamento(){
        if(signerManager->verificar()){
            string mensagem = "           |Desligando a Usina|\n\n-Assinaturas:\n";
            for (std::vector<ByteArray>::iterator it = signerManager->getAssinaturas().begin(); it != signerManager->getAssinaturas().end(); ++it) {
                ByteArray assinatura = *it;
                mensagem += assinatura.toHex() + "\n\n";
            }
            return mensagem;
            
        }else{
            return "|Impossivel desligar, nem todos assinaram|\n ";
        }
    }

};

#endif