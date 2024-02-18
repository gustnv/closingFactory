#include <libcryptosec/MessageDigest.h>
#include "challenge.hpp"

int main(int argc, char **argv) {
	cout << "-------------Challenge Labsec-------------\n" << endl;

	string nomeArquivo;
	cout << "Digite o nome/localizacao do arquivo: " << endl;
	cin >> nomeArquivo;

	// Crontole
	Controle controle = Controle(nomeArquivo);

    // Adicionando funcionarios 
	controle.adicionarPessoa("0005","Wiliam","senha5");
	controle.adicionarPessoa("0004","Gustavo","senha4");
	controle.adicionarPessoa("0003","Mateus","senha3");
	controle.adicionarPessoa("0002","Pedro","senha2");
	controle.adicionarPessoa("0001","Pedro","senha1");


	// Adicionar desligador
	controle.adicionarDesligador("0004", "senha4");
	controle.adicionarDesligador("0005", "senha5"); 
	controle.adicionarDesligador("0003", "senha3");
	controle.adicionarDesligador("0002", "senha2");
	controle.adicionarDesligador("0001", "senha1");

	// Tentativa de desligamento
	cout << controle.desligamento() << endl;


	return 0;
}
