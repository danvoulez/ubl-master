; RB-VM MVP - deny if age < 18
PushInput 0
CasGet
JsonNormalize
JsonValidate
JsonGetKey "age"
ConstI64 18
CmpI64 GE
AssertTrue
ConstBytes {"decision":"allow","rule":"A-18+"}
JsonNormalize
SetRcBody
PushInput 0
AttachProof
SignDefault
EmitRc
