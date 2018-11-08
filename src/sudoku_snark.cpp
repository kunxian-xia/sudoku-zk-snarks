//
// Created by xkx on 11/5/18.
//
#ifndef _SUDOKU_SNARK_CPP
#define _SUDOKU_SNARK_CPP

#define CURVE_ALT_BN128

#include "sudoku_snark.hpp"
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>

template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair()
{
    typedef libff::Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    sudoku_gadget<FieldT> g(pb, "sudoku_gadget");
    g.generate_r1cs_constraints();
    r1cs_constraint_system<FieldT> cs = pb.get_constraint_system();

#ifdef _DEBUG
    std::cout << "Number of R1CS constraints: " << cs.num_constraints() << std::endl;
#endif
    return r1cs_ppzksnark_generator<ppzksnark_ppT>(cs);
}

template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                    std::vector<int> _inputs_a, std::vector<int> _inputs_b,
                                                                    std::vector<int> _inputs_c, std::vector<int> _inputs_d)
{
    typedef libff::Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    sudoku_gadget<FieldT> g(pb, "sudoku_gadget");
    g.generate_r1cs_constraints();
    g.generate_r1cs_witness(_inputs_a, _inputs_b, _inputs_c, _inputs_d);

    if (!pb.is_satisfied()) {
        std::cout << "pb is not satisfied" << std::endl;
        return boost::none;
    }

    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                  int a21, int b11, int b22,
                  int c11, int c22, int d21)
{
    typedef libff::Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = {FieldT(a21), FieldT(b11), FieldT(b22),
                                              FieldT(c11), FieldT(c22), FieldT(d21)};

    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}

#endif
