#include "main.h"

namespace offsets {
	uintptr_t List = 0;
	uintptr_t Head = 0x8;
	uintptr_t Vgs = 0x30;
	uintptr_t Ftv = 0xc0;
}

static int countvalidnodes( uintptr_t Start, uintptr_t VgsOff ) {
	std::set<uintptr_t> Seen;
	uintptr_t N = Start;
	int Hits = 0;
	for ( int i = 0; i < 3000 && driver.vm_isvalid( N ); i++ ) {
		if ( !Seen.insert( N ).second) break;
		std::string Nm = driver.readstring( N + 0x10 );
		if (driver.vm_isvalidname( Nm ) ) {
			uintptr_t G = driver.vm_read<uintptr_t>( N + VgsOff );
			if ( driver.vm_isvalid( G ) ) Hits++;
		}
		uintptr_t Nx = driver.vm_read<uintptr_t>( N );
		if ( Nx == N || !driver.vm_isvalid( Nx ) ) break;
		N = Nx;
	}
	return Hits;
}

static int SniffFtv( uintptr_t Start, uintptr_t VgsOff, uintptr_t Base ) {
	int Best = -1;
	size_t BestU = 0;
	uintptr_t Top = Base + 0x40000000ULL;

	for ( uintptr_t o = 0; o < 0x400; o += 8 ) {
		std::set<uintptr_t> Uniq, Seen;
		int Total = 0;
		uintptr_t N = Start;

		for ( int i = 0; i < 1500 && driver.vm_isvalid( N ); i++ ) {

			if (!Seen.insert(N).second) break;

			uintptr_t Vg = driver.vm_read< uintptr_t >( N + VgsOff );

			if ( driver.vm_isvalid( Vg ) ) {
				uintptr_t V = driver.vm_read<uintptr_t>( Vg + o );
				if ( V > Base && V < Top ) { Uniq.insert( V ); Total++; }
			}

			uintptr_t Nx = driver.vm_read< uintptr_t >( N );

			if ( Nx == N || !driver.vm_isvalid( Nx ) ) break;

			N = Nx;
		}

		if (Total >= 50 && Uniq.size() >= (size_t)(Total * 3 / 4) && Uniq.size() > BestU) {
			BestU = Uniq.size();
			Best = (int)o;
		}
	}
	return Best;
}

int main() {
	SetConsoleOutputCP(CP_UTF8);
	SetConsoleTitleA("FFlags Dumper");

	auto T0 = std::chrono::high_resolution_clock::now();

	DWORD Pid = driver.vm_getpid(L"RobloxPlayerBeta.exe");
	if (!driver.vm_attach(Pid)) {
		std::cout << "[-] roblox not in execution\n";
		getchar();
		return 1;
	}

	uintptr_t Base = driver.vm_getmodulebase(L"RobloxPlayerBeta.exe");
	std::cout << "[+] pid " << std::dec << driver.vm_procid << "\n"
		<< "[+] base " << std::hex << Base << "\n\n";

	struct Cand { uintptr_t Rva, H, V; int Score; };
	std::vector<Cand> Pool;
	int Hits = 0;

	uintptr_t HTries[] = { 0x8, 0x10, 0x18, 0x20 };
	uintptr_t VTries[] = { 0x30, 0x38, 0x28, 0x40, 0x48, 0x20, 0x50, 0x58 };

	std::cout << "[+] dumping...\n";

	for (uintptr_t cur = 0x4000000; cur < 0x40000000; cur += 0x4000) {
		size_t Want = min((size_t)0x4000, (size_t)(0x40000000 - cur));
		std::vector<uint8_t> Buf(Want);
		if (!driver.vmread_raw(Base + cur, Buf.data(), Want)) continue;

		uintptr_t* P = (uintptr_t*)Buf.data();
		for (size_t i = 0, n = Want / 8; i < n; i++) {
			uintptr_t M = P[i];
			if (!driver.vm_isvalid(M)) continue;
			if (driver.vm_read<uint32_t>(M) != 0x3F800000) continue;
			Hits++;

			uintptr_t Rva = cur + (i * 8);
			for ( uintptr_t h : HTries ) {
				uintptr_t Mst = driver.vm_read<uintptr_t>( M + h );
				if ( !driver.vm_isvalid( Mst ) ) continue;
				uintptr_t Hd = driver.vm_read<uintptr_t>( Mst );
				if ( !driver.vm_isvalid( Hd) ) continue;

				for ( uintptr_t v : VTries ) {
					int s = countvalidnodes( Hd, v );
					if ( s >= 50 ) Pool.push_back( { Rva, h, v, s } );
				}
			}
		}
	}

	//std::cout << "magic " << std::dec << Hits << "  cands " << Pool.size() << "\n";

	if (Pool.empty()) {
		std::cout << "[-] no chain matched\n";
		getchar();
		return 1;
	}

	std::sort(Pool.begin(), Pool.end(), [](const Cand& a, const Cand& b) {
		return a.Score > b.Score;
		});

	std::cout << "\nTOP:\n";
	for (size_t i = 0; i < min((size_t)5, Pool.size()); i++) {
		auto& c = Pool[i];
		std::cout << " " << std::dec << i
			<< ". RVA=" << std::hex << c.Rva
			<< " H=" << c.H << " V=" << c.V
			<< " SCORE=" << std::dec << c.Score << "\n";
	}
	std::cout << "\n";

	auto& Pk = Pool[0];
	offsets::List = Pk.Rva;
	offsets::Head = Pk.H;
	offsets::Vgs = Pk.V;

	uintptr_t Hp = driver.vm_read<uintptr_t>(Base + offsets::List);
	uintptr_t Mst = driver.vm_read<uintptr_t>(Hp + offsets::Head);
	uintptr_t Hd = driver.vm_read<uintptr_t>(Mst);

	int F = SniffFtv(Hd, offsets::Vgs, Base);
	if (F < 0) {
		std::cout << "ftv sniff failed\n";
		getchar();
		return 1;
	}
	offsets::Ftv = (uintptr_t)F;

	std::cout << "list " << std::hex << offsets::List
		<< "  head " << offsets::Head
		<< "  vgs " << offsets::Vgs
		<< "  ftv " << offsets::Ftv << "\n\n";

	uintptr_t Last = driver.vm_read<uintptr_t>(Mst + 0x8);
	uintptr_t Cur = Hd;

	std::ofstream Hpp("FFlags.hpp");
	//std::ofstream Js("FFlags.json");
	//std::ofstream Txt("FFlags.txt");
	bool First = true;

	Hpp << "// FFlags dumper made by hcrdso\n";
	Hpp << "// github.com/hcrdso\n\n";
	Hpp << "#pragma once\n\n";
	Hpp << "namespace FFlagOffsets\n{\n";
	Hpp << "    uintptr_t FFlagList   = 0x" << std::uppercase << std::hex << offsets::List << ";\n";
	Hpp << "    uintptr_t HeadPointer = 0x" << std::uppercase << std::hex << offsets::Head << ";\n";
	Hpp << "    uintptr_t ValueGetSet = 0x" << std::uppercase << std::hex << offsets::Vgs << ";\n";
	Hpp << "    uintptr_t FlagToValue = 0x" << std::uppercase << std::hex << offsets::Ftv << ";\n";
	Hpp << "}\n\nnamespace FFlags\n{\n";

	/*Js << "{\n";
	Js << "    \"_by\": \"urmom\",\n";
	Js << "    \"FFlagOffsets\": {\n";
	Js << "        \"FFlagList\":   \"0x" << std::uppercase << std::hex << offsets::List << "\",\n";
	Js << "        \"HeadPointer\": \"0x" << std::uppercase << std::hex << offsets::Head << "\",\n";
	Js << "        \"ValueGetSet\": \"0x" << std::uppercase << std::hex << offsets::Vgs << "\",\n";
	Js << "        \"FlagToValue\": \"0x" << std::uppercase << std::hex << offsets::Ftv << "\"\n";
	Js << "    },\n    \"FFlags\": {\n";*/

	/*Txt << "FFlagOffsets\n";
	Txt << "FFlagList: 0x" << std::uppercase << std::hex << offsets::List << "\n";
	Txt << "HeadPointer: 0x" << offsets::Head << "\n";
	Txt << "ValueGetSet: 0x" << offsets::Vgs << "\n";
	Txt << "FlagToValue: 0x" << offsets::Ftv << "\n\n";

	Txt << "FFlags\n";*/

	std::set<uintptr_t> Seen;
	int D = 0;

	while (driver.vm_isvalid(Cur) && Cur != Last) {
		if (!Seen.insert(Cur).second) break;

		std::string Nm = driver.readstring( Cur + 0x10 );
		uintptr_t Vg = driver.vm_read<uintptr_t>(Cur + offsets::Vgs);
		if (!driver.vm_isvalid(Vg)) {
			uintptr_t Nx = driver.vm_read<uintptr_t>(Cur);
			if (Nx == Cur) break;
			Cur = Nx;
			continue;
		}

		uintptr_t Vptr = driver.vm_read<uintptr_t>(Vg + offsets::Ftv);
		std::string Vs = driver.readstring(Vptr);

		if (driver.vm_isvalidname( Nm ) && Vs != "True" && Vs != "False" ) {
			uintptr_t Rv = Vptr - Base;
			if ( Rv > 0x10000 && Rv < 0x40000000ULL ) {
				for ( auto& c : Nm ) if ( !isalnum( ( unsigned char )c ) ) c = '_';

				Hpp << "    uintptr_t " << Nm << " = 0x" << std::uppercase << std::hex << Rv << ";\n";
				//if (!First) Js << ",\n"; else First = false;
				//Js << "        \"" << Nm << "\": \"0x" << std::uppercase << std::hex << Rv << "\"";
				//Txt << Nm << " = 0x" << std::uppercase << std::hex << Rv << "\n";
				D++;
			}
		}

		uintptr_t Nx = driver.vm_read<uintptr_t>(Cur);
		if (Nx == Cur) break;
		Cur = Nx;
	}

	//Js << "\n    }\n}";
	Hpp << "}\n";
	Hpp.close();
	//Js.close();
	//Txt.close();

	auto T1 = std::chrono::high_resolution_clock::now();
	auto Ms = std::chrono::duration_cast<std::chrono::milliseconds>(T1 - T0);

	std::cout << std::dec << D << " fflags in " << Ms.count() << "ms\n\n";
	std::cout << "dumped\n\n";

	system("pause");
	return 0;
}