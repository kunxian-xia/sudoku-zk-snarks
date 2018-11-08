//
// Created by xkx on 11/4/18.
//

#ifndef _SUDOKU_SNARK_HPP
#define _SUDOKU_SNARK_HPP

#include "sudoku_gadget.hpp"
#include <boost/optional.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

using namespace libsnark;

template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair();

template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                   std::vector<int> _inputs_a, std::vector<int> _inputs_b,
                                                   std::vector<int> _inputs_c, std::vector<int> _inputs_d);

template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                  int a21, int b11, int b22,
                  int c11, int c22, int d21);

#include "sudoku_snark.cpp"

#endif
